use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    str::FromStr,
};

use cosmian_crypto_core::{bytes_ser_de::Serializable, CsRng};
use rand::SeedableRng;

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

/// The callback signature is a kmac of the body of the request used to do
/// authorization (checking if this client can call this callback)
pub const CALLBACK_SIGNATURE_LENGTH: usize = 32;

/// This key is used to derive a new 32 bytes Kmac key.
pub const SIGNATURE_KEY_LENGTH: usize = 16;

pub const FINDEX_CLOUD_DEFAULT_DOMAIN: &str = "https://findex.cosmian.com";

/// Findex Cloud tokens are a string containing all information required to do
/// requests to Findex Cloud (except the label because it is a value changing a
/// lot).
///
/// The string is encoded as follow:
/// 1. `index_id` `INDEX_ID_LENGTH` chars (see `Token@index_id`)
/// 2. base64 representation of the different keys:
///     1. `SIGNATURE_KEY_LENGTH` bytes of findex master key (this key is never
/// sent to the Findex Cloud backend)
///     2. 1 byte prefix identifying the next key
///     3. `SIGNATURE_KEY_LENGTH` bytes of callback signature key
///     4. 1 byte prefix identifying the next key
///     5. …
///
/// Currently each callback have an associated signature key used in a kmac to
/// send request to the backend. These key are only used for authorization
/// and do not secure the index (the findex master key do). In the future, we
/// could do optimization to avoid having one key for each callback but we want
/// to disallow the server to differentiate a `fetch_entries` for a search or a
/// `fetch_entries` for an upsert while still allowing fine grain permissions.
pub(crate) struct Token {
    /// This ID identify an index inside the Findex Cloud backend
    /// We do not use auto-increment integer ID because we don't want to leak
    /// the number of indexes inside our database.
    /// We do not use UUID because the token is limited in space.
    /// The abritrary chosen length is `INDEX_ID_LENGTH`.
    index_id: String,

    pub(crate) findex_master_key: KeyingMaterial<MASTER_KEY_LENGTH>,

    fetch_entries_key: Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>,
    fetch_chains_key: Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>,
    upsert_entries_key: Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>,
    insert_chains_key: Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys = self.findex_master_key.to_vec();

        if let Some(fetch_entries_key) = &self.fetch_entries_key {
            keys.push(0);
            keys.extend(fetch_entries_key.as_ref());
        }

        if let Some(fetch_chains_key) = &self.fetch_chains_key {
            keys.push(1);
            keys.extend(fetch_chains_key.as_ref());
        }

        if let Some(upsert_entries_key) = &self.upsert_entries_key {
            keys.push(2);
            keys.extend(upsert_entries_key.as_ref());
        }

        if let Some(insert_chains_key) = &self.insert_chains_key {
            keys.push(3);
            keys.extend(insert_chains_key.as_ref());
        }

        write!(f, "{}{}", self.index_id, base64::encode(keys))
    }
}

impl FromStr for Token {
    type Err = FindexErr;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        let (index_id, tail) = token.split_at(INDEX_ID_LENGTH);
        let mut bytes = base64::decode(tail)
            .map_err(|_| {
                FindexErr::Other(format!(
                    "token {token} is not a valid base64 encoded string"
                ))
            })?
            .into_iter();

        let findex_master_key = KeyingMaterial::try_from_bytes(
            &bytes.next_chunk::<MASTER_KEY_LENGTH>().map_err(|_| {
                FindexErr::Other(
                    "the token is too short, cannot read the Findex master key".to_owned(),
                )
            })?,
        )?;

        let mut token = Token {
            index_id: index_id.to_owned(),
            findex_master_key,

            fetch_entries_key: None,
            fetch_chains_key: None,
            upsert_entries_key: None,
            insert_chains_key: None,
        };

        while let Some(prefix) = bytes.next() {
            let key = Some(
                bytes
                    .next_chunk::<SIGNATURE_KEY_LENGTH>()
                    .map_err(|_| {
                        FindexErr::Other(format!(
                            "the token is too short, expecting {SIGNATURE_KEY_LENGTH} bytes after \
                             the prefix {prefix}"
                        ))
                    })?
                    .into(),
            );

            if prefix == 0 {
                token.fetch_entries_key = key;
            } else if prefix == 1 {
                token.fetch_chains_key = key;
            } else if prefix == 2 {
                token.upsert_entries_key = key;
            } else if prefix == 3 {
                token.insert_chains_key = key;
            } else {
                return Err(FindexErr::Other(format!(
                    "the token contains a unknown prefix {prefix}"
                )));
            }
        }

        Ok(token)
    }
}

impl Token {
    pub fn random_findex_master_key(
        index_id: String,
        fetch_entries_key: KeyingMaterial<SIGNATURE_KEY_LENGTH>,
        fetch_chains_key: KeyingMaterial<SIGNATURE_KEY_LENGTH>,
        upsert_entries_key: KeyingMaterial<SIGNATURE_KEY_LENGTH>,
        insert_chains_key: KeyingMaterial<SIGNATURE_KEY_LENGTH>,
    ) -> Result<Self, FindexErr> {
        let mut rng = CsRng::from_entropy();
        let findex_master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::new(&mut rng);

        Ok(Token {
            index_id,
            findex_master_key,
            fetch_entries_key: Some(fetch_entries_key),
            fetch_chains_key: Some(fetch_chains_key),
            upsert_entries_key: Some(upsert_entries_key),
            insert_chains_key: Some(insert_chains_key),
        })
    }

    pub fn reduce_permissions(&mut self, search: bool, index: bool) -> Result<(), FindexErr> {
        self.fetch_entries_key =
            reduce_option("fetch entries", &self.fetch_entries_key, search || index)?;
        self.fetch_chains_key = reduce_option("fetch chains", &self.fetch_chains_key, search)?;
        self.upsert_entries_key = reduce_option("upsert entries", &self.upsert_entries_key, index)?;
        self.insert_chains_key = reduce_option("insert chains", &self.insert_chains_key, index)?;

        Ok(())
    }
}

/// If we have the permission and want to keep it, do nothing.
/// If we don't have the permission and want to keep it, fail.
/// If we don't want to keep it, return none.
fn reduce_option(
    debug_info: &str,
    permission: &Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>,
    keep: bool,
) -> Result<Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>>, FindexErr> {
    match (permission, keep) {
        (_, false) => Ok(None),

        (Some(permission), true) => Ok(Some(permission.clone())),
        (None, true) => Err(FindexErr::Other(format!(
            "The token provided doesn't have the permission to {debug_info}"
        ))),
    }
}

enum Callback {
    FetchEntries,
    FetchChains,
    UpsertEntries,
    InsertChains,
}

impl Callback {
    pub fn get_uri(&self) -> &'static str {
        match self {
            Callback::FetchEntries => "fetch_entries",
            Callback::FetchChains => "fetch_chains",
            Callback::UpsertEntries => "upsert_entries",
            Callback::InsertChains => "insert_chains",
        }
    }

    pub fn get_key<'a>(
        &self,
        token: &'a Token,
    ) -> &'a Option<KeyingMaterial<SIGNATURE_KEY_LENGTH>> {
        match self {
            Callback::FetchEntries => &token.fetch_entries_key,
            Callback::FetchChains => &token.fetch_chains_key,
            Callback::UpsertEntries => &token.upsert_entries_key,
            Callback::InsertChains => &token.insert_chains_key,
        }
    }
}

impl FindexCloud {
    pub fn new(token: String, base_url: Option<String>) -> Result<Self, FindexErr> {
        Ok(FindexCloud {
            token: Token::from_str(&token)?,
            base_url,
        })
    }

    async fn post(&self, callback: Callback, bytes: &[u8]) -> Result<Vec<u8>, FindexErr> {
        let endpoint = callback.get_uri();

        let key: KmacKey = callback
            .get_key(&self.token)
            .as_ref()
            .ok_or(FindexErr::Other(format!(
                "your key doesn't have the permission to call {endpoint}"
            )))?
            .derive_kmac_key(self.token.index_id.as_bytes());

        let signature = base64::encode(kmac!(CALLBACK_SIGNATURE_LENGTH, &key, bytes));

        let url = format!(
            "{}/indexes/{}/{endpoint}",
            self.base_url
                .as_deref()
                .unwrap_or(FINDEX_CLOUD_DEFAULT_DOMAIN),
            self.token.index_id,
        );

        let client = reqwest::Client::new();
        let res = client
            .post(url)
            .header("X-Findex-Cloud-Signature", &signature)
            .body(bytes.to_vec())
            .send()
            .await
            .map_err(|err| {
                FindexErr::Other(format!(
                    "Impossible to send the request to FindexCloud: {err}"
                ))
            })?;

        Ok(res
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

        let bytes = self.post(Callback::FetchEntries, &serialized_uids).await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_uids = serialize_set(chain_table_uids)?;

        let bytes = self.post(Callback::FetchChains, &serialized_uids).await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_upsert = items.try_to_bytes()?;

        let bytes = self
            .post(Callback::UpsertEntries, &serialized_upsert)
            .await?;

        EncryptedTable::try_from_bytes(&bytes)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let serialized_insert = items.try_to_bytes()?;

        self.post(Callback::InsertChains, &serialized_insert)
            .await?;

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
