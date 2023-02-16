#[cfg(not(feature = "wasm_bindgen"))]
use std::time::SystemTime;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    str::FromStr,
};

use cosmian_crypto_core::{bytes_ser_de::Serializable, reexport::rand_core::SeedableRng, CsRng};
#[cfg(feature = "wasm_bindgen")]
use js_sys::Date;
use reqwest::Client;

use crate::{
    core::{
        EncryptedTable, FindexCallbacks, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial,
        Keyword, Uid, UpsertData,
    },
    error::FindexErr,
    interfaces::{
        generic_parameters::{
            DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
            MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
        },
        ser_de::serialize_set,
    },
    kmac,
};

pub(crate) struct FindexCloud {
    pub(crate) token: Token,
    pub(crate) base_url: Option<String>,
}

/// See `Token@index_id`
pub const INDEX_ID_LENGTH: usize = 5;

/// The callback signature is a kmac of the body of the request.
/// It is used to assert the client can call this callback.
pub const CALLBACK_SIGNATURE_LENGTH: usize = 32;

/// The number of seconds of validity of the requests to the Findex Cloud
/// backend. After this time, the request cannot be accepted by the backend.
/// This is done to prevent replay attacks.
pub const REQUEST_SIGNATURE_TIMEOUT_AS_SECS: u64 = 60;

/// This seed is used to derive a new 32 bytes Kmac key.
pub const SIGNATURE_SEED_LENGTH: usize = 16;

pub const FINDEX_CLOUD_DEFAULT_DOMAIN: &str = "https://findex.cosmian.com";

/// Findex Cloud tokens are a string containing all information required to do
/// requests to Findex Cloud (except the label because it is a value changing a
/// lot).
///
/// The string is encoded as follow:
/// 1. `index_id` `INDEX_ID_LENGTH` chars (see `Token@index_id`)
/// 2. base64 representation of the different keys:
///     1. `MASTER_KEY_LENGTH` bytes of findex master key (this key is never
/// sent to the Findex Cloud backend)
///     2. 1 byte prefix identifying the next key
///     3. `SIGNATURE_SEED_LENGTH` bytes of callback signature key
///     4. 1 byte prefix identifying the next key
///     5. …
///
/// Currently each callback has an associated signature key used in a kmac to
/// send request to the backend. These key are only used for authorization
/// and do not secure the index (the findex master key do). In the future, we
/// could do optimization to avoid having one key for each callback but we want
/// to disallow the server to differentiate a `fetch_entries` for a search or a
/// `fetch_entries` for an upsert while still allowing fine grain permissions.
pub(crate) struct Token {
    /// This ID identifies an index inside the Findex Cloud backend
    /// This number is not sensitive, it's only an ID. If someone finds this ID,
    /// it cannot do requests on the index because it doesn't have the keys.
    /// We do not use auto-increment integer ID because we don't want to leak
    /// the number of indexes inside our database.
    /// We do not use UUID because the token is limited in space.
    /// The arbitrary chosen length is `INDEX_ID_LENGTH`.
    index_id: String,

    pub(crate) findex_master_key: KeyingMaterial<MASTER_KEY_LENGTH>,

    fetch_entries_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    fetch_chains_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    upsert_entries_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    insert_chains_seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut size = self.findex_master_key.len();
        for callback in Callback::ALL {
            size += self.get_seed(callback).map_or(0, |seed| seed.len() + 1);
        }

        let mut seeds = Vec::with_capacity(size);
        seeds.extend(self.findex_master_key.as_ref());

        for callback in Callback::ALL {
            if let Some(seed) = self.get_seed(callback) {
                seeds.push(callback as u8);
                seeds.extend(seed.as_ref());
            }
        }

        write!(f, "{}{}", self.index_id, base64::encode(seeds))
    }
}

impl FromStr for Token {
    type Err = FindexErr;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (index_id, tail) = token.split_at(INDEX_ID_LENGTH);
        let mut bytes = base64::decode(tail)
            .map_err(|_| {
                FindexErr::Other(format!(
                    "token '{token}' is malformed, the keys section is not base64 encoded."
                ))
            })?
            .into_iter();
        let original_length = bytes.len();

        let findex_master_key = KeyingMaterial::try_from_bytes(
            &bytes.next_chunk::<MASTER_KEY_LENGTH>().map_err(|_| {
                FindexErr::Other(
                    "token '{token}' is malformed, cannot read the Findex master key at the \
                     beginning of the keys section"
                        .to_owned(),
                )
            })?,
        )?;

        let mut token = Token {
            index_id: index_id.to_owned(),
            findex_master_key,

            fetch_entries_seed: None,
            fetch_chains_seed: None,
            upsert_entries_seed: None,
            insert_chains_seed: None,
        };

        while let Some(prefix) = bytes.next() {
            let seed = Some(
                bytes
                    .next_chunk::<SIGNATURE_SEED_LENGTH>()
                    .map_err(|_| {
                        FindexErr::Other(format!(
                            "token '{token}' is malformed, expecting {SIGNATURE_SEED_LENGTH} \
                             bytes after the prefix {prefix} at keys section offset {}",
                            original_length - bytes.len() - 1
                        ))
                    })?
                    .into(),
            );

            let callback: Callback = prefix.try_into().map_err(|_| {
                FindexErr::Other(format!(
                    "token '{token}' is malformed, it contains a unknown prefix {prefix} at keys \
                     section offset {}",
                    original_length - bytes.len() - 1
                ))
            })?;

            token.set_seed(callback, seed);
        }

        Ok(token)
    }
}

impl Token {
    pub fn random_findex_master_key(
        index_id: String,
        fetch_entries_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        fetch_chains_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        upsert_entries_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
        insert_chains_seed: KeyingMaterial<SIGNATURE_SEED_LENGTH>,
    ) -> Result<Self, FindexErr> {
        let mut rng = CsRng::from_entropy();
        let findex_master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::new(&mut rng);

        Ok(Token {
            index_id,
            findex_master_key,
            fetch_entries_seed: Some(fetch_entries_seed),
            fetch_chains_seed: Some(fetch_chains_seed),
            upsert_entries_seed: Some(upsert_entries_seed),
            insert_chains_seed: Some(insert_chains_seed),
        })
    }

    pub fn reduce_permissions(&mut self, search: bool, index: bool) -> Result<(), FindexErr> {
        self.fetch_entries_seed =
            reduce_option("fetch entries", &self.fetch_entries_seed, search || index)?;
        self.fetch_chains_seed = reduce_option("fetch chains", &self.fetch_chains_seed, search)?;
        self.upsert_entries_seed =
            reduce_option("upsert entries", &self.upsert_entries_seed, index)?;
        self.insert_chains_seed = reduce_option("insert chains", &self.insert_chains_seed, index)?;

        Ok(())
    }

    fn get_seed(&self, callback: Callback) -> Option<&KeyingMaterial<SIGNATURE_SEED_LENGTH>> {
        match callback {
            Callback::FetchEntries => &self.fetch_entries_seed,
            Callback::FetchChains => &self.fetch_chains_seed,
            Callback::UpsertEntries => &self.upsert_entries_seed,
            Callback::InsertChains => &self.insert_chains_seed,
        }
        .as_ref()
    }

    fn get_key(&self, callback: Callback) -> Option<KmacKey> {
        self.get_seed(callback)
            .map(|seed| seed.derive_kmac_key(self.index_id.as_bytes()))
    }

    fn set_seed(
        &mut self,
        callback: Callback,
        seed: Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    ) {
        match callback {
            Callback::FetchEntries => self.fetch_entries_seed = seed,
            Callback::FetchChains => self.fetch_chains_seed = seed,
            Callback::UpsertEntries => self.upsert_entries_seed = seed,
            Callback::InsertChains => self.insert_chains_seed = seed,
        }
    }
}

/// If we have the permission and want to keep it, do nothing.
/// If we don't have the permission and want to keep it, fail.
/// If we don't want to keep it, return none.
fn reduce_option(
    debug_info: &str,
    permission: &Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>,
    keep: bool,
) -> Result<Option<KeyingMaterial<SIGNATURE_SEED_LENGTH>>, FindexErr> {
    match (permission, keep) {
        (_, false) => Ok(None),

        (Some(permission), true) => Ok(Some(permission.clone())),
        (None, true) => Err(FindexErr::Other(format!(
            "The token provided doesn't have the permission to {debug_info}"
        ))),
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Callback {
    FetchEntries = 0,
    FetchChains = 1,
    UpsertEntries = 2,
    InsertChains = 3,
}

impl Callback {
    const ALL: [Callback; 4] = [
        Self::FetchEntries,
        Self::FetchChains,
        Self::UpsertEntries,
        Self::InsertChains,
    ];

    pub fn get_uri(self) -> &'static str {
        match self {
            Callback::FetchEntries => "fetch_entries",
            Callback::FetchChains => "fetch_chains",
            Callback::UpsertEntries => "upsert_entries",
            Callback::InsertChains => "insert_chains",
        }
    }
}

impl TryFrom<u8> for Callback {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Callback::FetchEntries),
            1 => Ok(Callback::FetchChains),
            2 => Ok(Callback::UpsertEntries),
            3 => Ok(Callback::InsertChains),
            _ => Err(()),
        }
    }
}

impl Display for Callback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Callback::FetchEntries => write!(f, "fetch entries"),
            Callback::FetchChains => write!(f, "fetch chains"),
            Callback::UpsertEntries => write!(f, "upsert entries"),
            Callback::InsertChains => write!(f, "insert chains"),
        }
    }
}

impl FindexCloud {
    pub fn new(token: &str, base_url: Option<String>) -> Result<Self, FindexErr> {
        Ok(FindexCloud {
            token: Token::from_str(token)?,
            base_url,
        })
    }

    async fn post(&self, callback: Callback, bytes: Vec<u8>) -> Result<Vec<u8>, FindexErr> {
        let key = self.token.get_key(callback).ok_or_else(|| {
            FindexErr::Other(format!(
                "your token '{}' doesn't have the permission to call {callback}",
                self.token
            ))
        })?;

        // SystemTime::now() panics in WASM <https://github.com/rust-lang/rust/issues/48564>
        #[cfg(feature = "wasm_bindgen")]
        let current_timestamp = (Date::now() / 1000.0) as u64; // Date::now() returns milliseconds

        #[cfg(not(feature = "wasm_bindgen"))]
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| FindexErr::Other("SystemTime is before UNIX_EPOCH".to_owned()))?
            .as_secs();

        let expiration_timestamp_bytes =
            (current_timestamp + REQUEST_SIGNATURE_TIMEOUT_AS_SECS).to_be_bytes();

        let signature = kmac!(
            CALLBACK_SIGNATURE_LENGTH,
            &key,
            &expiration_timestamp_bytes,
            &bytes
        );

        let mut body =
            Vec::with_capacity(signature.len() + expiration_timestamp_bytes.len() + bytes.len());
        body.extend_from_slice(&signature);
        body.extend_from_slice(&expiration_timestamp_bytes);
        body.extend_from_slice(&bytes);

        let url = format!(
            "{}/indexes/{}/{}",
            self.base_url
                .as_deref()
                .unwrap_or(FINDEX_CLOUD_DEFAULT_DOMAIN),
            self.token.index_id,
            callback.get_uri(),
        );

        let response = Client::new()
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|err| {
                FindexErr::Other(format!(
                    "Impossible to send the request to FindexCloud: {err}"
                ))
            })?;

        if !response.status().is_success() {
            return Err(FindexErr::Other(format!(
                "request to Findex Cloud failed, status code is {}, response is {}",
                response.status(),
                response
                    .text()
                    .await
                    .unwrap_or_else(|_| "cannot parse response".to_owned())
            )));
        }

        Ok(response
            .bytes()
            .await
            .map_err(|err| {
                FindexErr::Other(format!(
                    "Impossible to read the returned bytes from FindexCloud:  {err}"
                ))
            })?
            .to_vec())
    }
}

impl FindexCallbacks<UID_LENGTH> for FindexCloud {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexErr> {
        Ok(true)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_uids = serialize_set(entry_table_uids)?;

        let bytes = self.post(Callback::FetchEntries, serialized_uids).await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_uids = serialize_set(chain_table_uids)?;

        let bytes = self.post(Callback::FetchChains, serialized_uids).await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_upsert = items.try_to_bytes()?;

        let bytes = self
            .post(Callback::UpsertEntries, serialized_upsert)
            .await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let serialized_insert = items.try_to_bytes()?;

        self.post(Callback::InsertChains, serialized_insert).await?;

        Ok(())
    }

    fn update_lines(
        &mut self,
        _chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        todo!("update lines not implemented in WASM")
    }

    fn list_removed_locations(
        &self,
        _locations: &HashSet<crate::core::Location>,
    ) -> Result<HashSet<crate::core::Location>, FindexErr> {
        todo!("list removed locations not implemented in WASM")
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, FindexErr> {
        todo!("fetch all entry table uids not implemented in WASM")
    }
}

impl
    FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
    > for FindexCloud
{
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
    > for FindexCloud
{
}
