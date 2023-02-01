use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use js_sys::Uint8Array;
use tiny_keccak::{Hasher, Kmac};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::{
    core::{
        EncryptedTable, FindexCallbacks, FindexSearch, FindexUpsert, IndexedValue, Keyword, Uid,
        UpsertData,
    },
    error::FindexErr,
    interfaces::{
        generic_parameters::{
            DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
            MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
        },
        ser_de::serialize_set,
    },
};

pub(crate) struct FindexCloud {
    pub(crate) token: Token,
    pub(crate) url: Option<String>,
}

pub struct Token {
    index_id: String,

    pub(crate) findex_master_key: [u8; 16],

    fetch_entries_key: Option<[u8; 16]>,
    fetch_chains_key: Option<[u8; 16]>,
    upsert_entries_key: Option<[u8; 16]>,
    insert_chains_key: Option<[u8; 16]>,
}

enum Callback {
    FetchEntries,
    FetchChains,
    UpsertEntries,
    InsertChains,
}

impl FindexCloud {
    pub fn new(token: String, url: Option<String>) -> Result<Self, FindexErr> {
        let (index_id, tail) = token.split_at(5);
        let mut bytes = tail.bytes();

        let findex_master_key = bytes.next_chunk::<16>().map_err(|_| {
            FindexErr::Other("the token is too short, cannot read the Findex master key".to_owned())
        })?;

        let mut token = Token {
            index_id: index_id.to_owned(),
            findex_master_key,

            fetch_entries_key: None,
            fetch_chains_key: None,
            upsert_entries_key: None,
            insert_chains_key: None,
        };

        while let Some(prefix) = bytes.next() {
            if prefix == 0 {
                token.fetch_entries_key = Some(bytes.next_chunk::<16>().map_err(|_| {
                    FindexErr::Other(format!(
                        "the token is too short, expecting 16 bytes after the prefix {prefix}"
                    ))
                })?);
            } else if prefix == 1 {
                token.fetch_chains_key = Some(bytes.next_chunk::<16>().map_err(|_| {
                    FindexErr::Other(format!(
                        "the token is too short, expecting 16 bytes after the prefix {prefix}"
                    ))
                })?);
            } else if prefix == 2 {
                token.upsert_entries_key = Some(bytes.next_chunk::<16>().map_err(|_| {
                    FindexErr::Other(format!(
                        "the token is too short, expecting 16 bytes after the prefix {prefix}"
                    ))
                })?);
            } else if prefix == 3 {
                token.insert_chains_key = Some(bytes.next_chunk::<16>().map_err(|_| {
                    FindexErr::Other(format!(
                        "the token is too short, expecting 16 bytes after the prefix {prefix}"
                    ))
                })?);
            } else {
                return Err(FindexErr::Other(format!(
                    "the token contains a unknown prefix {prefix}"
                )));
            }
        }

        Ok(FindexCloud { token, url })
    }

    async fn post(&self, callback: Callback, bytes: &[u8]) -> Result<Vec<u8>, FindexErr> {
        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::Cors);
        opts.body(Some(&JsValue::from(unsafe { Uint8Array::view(bytes) })));

        let endpoint = match callback {
            Callback::FetchEntries => "fetch_entries",
            Callback::FetchChains => "fetch_chains",
            Callback::UpsertEntries => "upsert_entries",
            Callback::InsertChains => "insert_chains",
        };

        let key = match callback {
            Callback::FetchEntries => self.token.fetch_entries_key,
            Callback::FetchChains => self.token.fetch_chains_key,
            Callback::UpsertEntries => self.token.upsert_entries_key,
            Callback::InsertChains => self.token.insert_chains_key,
        }
        .ok_or(FindexErr::Other(format!(
            "your key doesn't have the permission to call {endpoint}"
        )))?;

        let mut hasher = Kmac::v128(&key, &[]);
        let mut output = [0u8; 32];
        hasher.update(bytes);
        hasher.finalize(&mut output);

        let signature = hex::encode(output);

        let url = format!(
            "{}/index/{}/{endpoint}",
            self.url.as_deref().unwrap_or("http://localhost:8000"),
            self.token.index_id,
        );

        let request = Request::new_with_str_and_init(&url, &opts)?;

        request
            .headers()
            .set("X-Findex-Cloud-Signature", &signature)?;

        let window = web_sys::window().unwrap();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

        // `resp_value` is a `Response` object.
        assert!(resp_value.is_instance_of::<Response>());
        let resp: Response = resp_value.dyn_into().unwrap();

        let buffer = JsFuture::from(resp.array_buffer()?).await?;
        let array = Uint8Array::new(&buffer);

        Ok(array.to_vec())
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
