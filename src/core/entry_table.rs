//! Defines all structures and methods specific to the Entry Table.
//!
//! The Entry Table indexes chains of values stored in the Chain Table. Each
//! chain is associated to a keyword and is indexed by a unique item in the
//! Entry Table. The UID of this item is obtained by deriving the hash of the
//! associated keyword.

use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializer},
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, SymKey},
};
use zeroize::Zeroize;

use super::structs::Block;
use crate::{
    core::{
        chain_table::{ChainTable, ChainTableValue, KwiChainUids},
        keys::KeyCache,
        structs::{EncryptedTable, IndexedValue, Label, Uid},
        KeyingMaterial, Keyword, CHAIN_TABLE_KEY_DERIVATION_INFO,
    },
    error::FindexErr,
};

/// A value of the Entry Table.
///
/// All Entry Table values are of equal lengths. They are used to store:
/// - the UID of the last Chain Table line of the indexed chain;
/// - the keying material used to derive DEM and KMAC keys for the chain.
/// - the hash of the indexing keyword;
///
/// # Attributes
///
/// - `chain_table_uid` : Chain Table UID
/// - `kwi`             : symmetric key associated to the indexed `Keyword`
/// - `keyword_hash`    : hash of the indexing `Keyword`
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryTableValue<const UID_LENGTH: usize, const KWI_LENGTH: usize> {
    pub(crate) chain_table_uid: Uid<UID_LENGTH>,
    pub(crate) kwi: KeyingMaterial<KWI_LENGTH>,
    pub(crate) keyword_hash: [u8; Keyword::HASH_LENGTH],
}

impl<const UID_LENGTH: usize, const KWI_LENGTH: usize> EntryTableValue<UID_LENGTH, KWI_LENGTH> {
    /// Creates a new Entry Table value for the keyword which hash is given.
    ///
    /// - `rng`             : random number generator
    /// - `keyword_hash`    : hash of the indexing keyword
    #[inline]
    pub(crate) fn new<
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
    >(
        rng: &mut impl CryptoRngCore,
        keyword_hash: [u8; Keyword::HASH_LENGTH],
    ) -> Self {
        let kwi = KeyingMaterial::new(rng);
        let kwi_uid: KmacKey = kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
        let chain_table_uid =
            ChainTable::<UID_LENGTH, BLOCK_LENGTH>::generate_uid(&kwi_uid, &keyword_hash);
        Self {
            chain_table_uid,
            kwi,
            keyword_hash,
        }
    }

    /// Computes the next UID of the indexed chain. Updates the Entry Table
    /// value and returns this UID.
    ///
    /// - `kwi_uid` : KMAC key used to generate Chain Table UIDs.
    #[inline]
    pub(crate) fn next_chain_table_uid<
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
    >(
        &mut self,
        kwi_uid: &KmacKey,
    ) -> &Uid<UID_LENGTH> {
        self.chain_table_uid =
            ChainTable::<UID_LENGTH, BLOCK_LENGTH>::generate_uid(kwi_uid, &self.chain_table_uid);
        &self.chain_table_uid
    }

    /// Adds the given `IndexedValue` to the indexed chain. Updates this Entry
    /// Table value and its chain in the given encrypted Chain Table.
    ///
    /// # Parameters
    ///
    /// - `indexed_value`   : `IndexedValue` to add to the Chain Table
    /// - `kwi_uid`         : KMAC key used to generate chain UIDs
    /// - `kwi_value`       : DEM key used to encrypt Chain Table values
    /// - `chain_table`     : Chain Table to which to upsert the given value
    /// - `rng`             : random number generator
    pub fn upsert_indexed_value<
        const BLOCK_LENGTH: usize,
        const TABLE_WIDTH: usize,
        const KMAC_KEY_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &mut self,
        indexed_value: &IndexedValue,
        // TODO (TBZ): this should be an `Option` (it can be recomputed from the Entry Table
        // value).
        kwi_uid: &KmacKey,
        // TODO (TBZ): this should be an `Option` (it can be recomputed from the Entry Table
        // value).
        kwi_value: &DemScheme::Key,
        chain_table: &mut EncryptedTable<UID_LENGTH>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(), FindexErr> {
        let mut chain_table_value =
            if let Some(encrypted_chain_table_value) = chain_table.get(&self.chain_table_uid) {
                ChainTableValue::<BLOCK_LENGTH>::decrypt::<TABLE_WIDTH, DEM_KEY_LENGTH, DemScheme>(
                    kwi_value,
                    encrypted_chain_table_value,
                )?
            } else {
                // This the first time a value is indexed for this `Keyword`.
                ChainTableValue::new::<TABLE_WIDTH>(vec![])?
            };

        for block in Block::pad(&indexed_value.to_vec())? {
            if chain_table_value.len() < TABLE_WIDTH {
                // There is still room for a new `Block`.
                chain_table_value.push(block);
            } else {
                // Encrypt and insert the current value in the Chain Table.
                let encrypted_chain_table_value = chain_table_value
                    .encrypt::<TABLE_WIDTH, DEM_KEY_LENGTH, DemScheme>(kwi_value, rng)?;
                chain_table.insert(self.chain_table_uid.clone(), encrypted_chain_table_value);
                // Start a new line in the chain.
                self.next_chain_table_uid::<BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(kwi_uid);
                chain_table_value = ChainTableValue::new::<TABLE_WIDTH>(vec![block])?;
            }
        }

        // Encrypt and insert the value in the Chain Table.
        let encrypted_chain_table_value =
            chain_table_value.encrypt::<TABLE_WIDTH, DEM_KEY_LENGTH, DemScheme>(kwi_value, rng)?;
        chain_table.insert(self.chain_table_uid.clone(), encrypted_chain_table_value);
        Ok(())
    }

    /// Encrypts the `EntryTableValue` using the given `𝐾_value`.
    ///
    /// - `k_value` : `𝐾_value`
    /// - `rng`     : random number generator
    #[inline]
    pub(crate) fn encrypt<
        const BLOCK_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &self,
        k_value: &DemScheme::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, FindexErr> {
        let mut ser = Serializer::new();
        ser.write_array(&self.chain_table_uid)?;
        ser.write_array(&self.kwi)?;
        ser.write_array(&self.keyword_hash)?;
        DemScheme::encrypt(rng, k_value, &ser.finalize(), None).map_err(FindexErr::from)
    }

    /// Decrypts an encrypted `EntryTableValue` using the given `𝐾_value`.
    ///
    /// - `k_value`     : `𝐾_value`
    /// - `ciphertext`  : encrypted entry table value
    #[inline]
    pub(crate) fn decrypt<
        const BLOCK_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        k_value: &DemScheme::Key,
        ciphertext: &[u8],
    ) -> Result<Self, FindexErr> {
        let bytes = DemScheme::decrypt(k_value, ciphertext, None)?;
        let mut de = Deserializer::new(&bytes);
        let chain_table_uid = de.read_array::<UID_LENGTH>()?;
        let kwi = de.read_array::<KWI_LENGTH>()?;
        let keyword_hash = de.read_array::<{ Keyword::HASH_LENGTH }>()?;
        Ok(Self {
            chain_table_uid: chain_table_uid.into(),
            kwi: kwi.into(),
            keyword_hash,
        })
    }

    /// Gets all UIDs of the chain indexed by this Entry Table value.
    ///
    /// The first UID is derived from the hash of the indexing keyword stored in
    /// the Entry Table value. Subsequent UIDs are derived from the previous UID
    /// in the chain.
    ///
    /// Stops when the derived UID matches the one stored in the Entry Table
    /// value or the `max_results_per_keyword` has been reached.
    ///
    /// Inserts the couple `(𝐾_{𝑤_𝑖}, ChainTableUid)` to the given map in-place.
    ///
    /// # Parameters
    ///
    /// - `max_results`             : maximum number of results to fetch
    /// - `kwi_chain_table_uids`    : (output) maps the `𝐾_{𝑤_𝑖}` with the Chain
    ///   Table UIDs
    pub(crate) fn unchain<
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &self,
        max_results: usize,
        kwi_chain_table_uids: &mut KwiChainUids<UID_LENGTH, KWI_LENGTH>,
    ) {
        let kwi_uid: KmacKey = self.kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        let entry = kwi_chain_table_uids
            .entry(self.kwi.clone())
            .or_insert_with(Vec::new);

        // derive the Chain Table UID
        let mut current_chain_table_uid =
            ChainTable::<UID_LENGTH, BLOCK_LENGTH>::generate_uid(&kwi_uid, &self.keyword_hash);

        for _ in 0..max_results {
            // add the new Chain Table UID to the map
            entry.push(current_chain_table_uid.clone());

            // return if we found the UID stored in the Entry Table value
            if current_chain_table_uid == self.chain_table_uid {
                break;
            }

            // compute the next UID
            current_chain_table_uid = ChainTable::<UID_LENGTH, BLOCK_LENGTH>::generate_uid(
                &kwi_uid,
                &current_chain_table_uid,
            );
        }
    }
}

impl<const UID_LENGTH: usize, const KEY_LENGTH: usize> Zeroize
    for EntryTableValue<UID_LENGTH, KEY_LENGTH>
{
    #[inline]
    fn zeroize(&mut self) {
        self.chain_table_uid.zeroize();
        self.kwi.zeroize();
        self.keyword_hash.zeroize();
    }
}

impl<const UID_LENGTH: usize, const KEY_LENGTH: usize> Drop
    for EntryTableValue<UID_LENGTH, KEY_LENGTH>
{
    #[inline]
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Entry Table.
#[derive(Debug, Default)]
pub struct EntryTable<const UID_LENGTH: usize, const KWI_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, EntryTableValue<UID_LENGTH, KWI_LENGTH>>,
);

impl<const UID_LENGTH: usize, const KWI_LENGTH: usize> Deref
    for EntryTable<UID_LENGTH, KWI_LENGTH>
{
    type Target = HashMap<Uid<UID_LENGTH>, EntryTableValue<UID_LENGTH, KWI_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize, const KWI_LENGTH: usize> DerefMut
    for EntryTable<UID_LENGTH, KWI_LENGTH>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize, const KWI_LENGTH: usize> EntryTable<UID_LENGTH, KWI_LENGTH> {
    /// Creates a new Entry Table with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Builds an `EntryTableUid` from the given hash value, symmetric key and
    /// `Label`. The hash value given *should* be the one of the indexing
    /// keyword.
    ///
    /// - `key`             : KMAC key
    /// - `keyword_hash`    : `Keyword` to hash
    /// - `label`           : additional information used during the derivation
    #[inline]
    pub fn generate_uid<const KMAC_KEY_LENGTH: usize, KmacKey: SymKey<KMAC_KEY_LENGTH>>(
        key: &KmacKey,
        keyword_hash: &[u8; Keyword::HASH_LENGTH],
        label: &Label,
    ) -> Uid<UID_LENGTH> {
        kmac!(UID_LENGTH, key.as_bytes(), keyword_hash, label).into()
    }

    /// Decrypts an Entry Table with the given `K_value`.
    ///
    /// - `k_value`                 : DEM key
    /// - `encrypted_entry_table`   : encrypted Entry Table
    pub fn decrypt<
        const BLOCK_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        k_value: &DemScheme::Key,
        encrypted_entry_table: &EncryptedTable<UID_LENGTH>,
    ) -> Result<Self, FindexErr> {
        let mut entry_table = Self::with_capacity(encrypted_entry_table.len());
        for (k, v) in encrypted_entry_table.iter() {
            let decrypted_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::decrypt::<
                BLOCK_LENGTH,
                DEM_KEY_LENGTH,
                DemScheme,
            >(k_value, v)
            .map_err(|_| {
                FindexErr::CallBack(format!(
                    "fail to decrypt one of the `value` returned by the fetch entries callback \
                     (uid as hex was '{}', value {})",
                    hex::encode(&k),
                    if v.is_empty() {
                        "was empty".to_owned()
                    } else {
                        format!("as hex was '{}'", hex::encode(v))
                    },
                ))
            })?;

            entry_table.insert(k.clone(), decrypted_value);
        }
        Ok(entry_table)
    }

    /// Encrypts the Entry Table using the given `K_value`.
    ///
    /// - `k_value` : DEM key
    /// - `rng`     : random number generator
    pub fn encrypt<
        const BLOCK_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &self,
        k_value: &DemScheme::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let mut encrypted_entry_table = EncryptedTable::with_capacity(self.len());
        for (k, v) in self.iter() {
            encrypted_entry_table.insert(
                k.clone(),
                EntryTableValue::<UID_LENGTH, KWI_LENGTH>::encrypt::<
                    BLOCK_LENGTH,
                    DEM_KEY_LENGTH,
                    DemScheme,
                >(v, k_value, rng)?,
            );
        }
        Ok(encrypted_entry_table)
    }

    /// Unchains the entries of this Entry Table with the given UIDs.
    ///
    /// - `uids`                : UIDs of the Entry Table entries to unchain
    /// - `max_results_per_uid` : maximum number of Chain Table UIDs to compute
    ///   per entry
    pub fn unchain<
        'a,
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &self,
        uids: impl Iterator<Item = &'a Uid<UID_LENGTH>>,
        max_results_per_uid: usize,
    ) -> KwiChainUids<UID_LENGTH, KWI_LENGTH> {
        let mut kwi_chain_table_uids = KwiChainUids::default();
        for entry_table_uid in uids {
            if let Some(value) = self.get(entry_table_uid) {
                value.unchain::<BLOCK_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
                    max_results_per_uid,
                    &mut kwi_chain_table_uids,
                );
            }
        }
        kwi_chain_table_uids
    }

    /// Refreshes the UIDs of the Entry Table using the given KMAC key and
    /// label.
    ///
    /// - `k_uid`   : KMAC key used to generate Entry Table UIDs
    /// - `label`   : additional information used during the derivation
    pub fn refresh_uids<const KMAC_KEY_LENGTH: usize, KmacKey: SymKey<KMAC_KEY_LENGTH>>(
        &mut self,
        k_uid: &KmacKey,
        label: &Label,
    ) {
        let mut res = Self::with_capacity(self.len());
        for (_, entry_table_value) in self.iter() {
            res.insert(
                Self::generate_uid(k_uid, &entry_table_value.keyword_hash, label),
                entry_table_value.clone(),
            );
        }
        *self = res;
    }

    /// Indexes the given values for the given keywords in this Entry Table.
    /// Returns a map of the upserted Entry Table items to their associated
    /// chain.
    ///
    /// # Parameters
    ///
    /// - `rng`                 : random number generator
    /// - `new_entries`         : map values to their indexing keywords
    /// - `keywords_to_upsert`  : map keywords to their derived Entry Table UID
    pub fn upsert<
        const BLOCK_LENGTH: usize,
        const TABLE_WIDTH: usize,
        const KMAC_KEY_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &mut self,
        rng: &mut impl CryptoRngCore,
        new_chain_elements: &HashMap<Keyword, HashSet<IndexedValue>>,
        entry_table_uid_cache: &HashMap<Keyword, Uid<UID_LENGTH>>,
    ) -> Result<HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>, FindexErr> {
        // Cache the KMAC and DEM keys
        let mut key_cache = KeyCache::with_capacity(entry_table_uid_cache.len());

        let mut chain_table_additions = HashMap::with_capacity(new_chain_elements.len());
        for (keyword, indexed_values) in new_chain_elements {
            // Get the corresponding Entry Table UID from the cache.
            let entry_table_uid = entry_table_uid_cache.get(keyword).ok_or_else(|| {
                FindexErr::CryptoError(format!(
                    "No entry in Entry Table UID cache for keyword '{keyword:?}'"
                ))
            })?;

            // It is only possible to insert new entries in the Chain Table.
            let new_chain_table_entries = chain_table_additions
                .entry(entry_table_uid.clone())
                .or_default();

            // Prepare the corresponding Entry Table value.
            let entry_table_value = self
                .entry(entry_table_uid.clone())
                .and_modify(|entry_table_value| {
                    // A chain is already indexed for this `Keyword`. Start a new line at the tip of
                    // the existing chain.
                    let (kwi_uid, _) = key_cache.get_entry_or_insert(
                        &entry_table_value.kwi,
                        CHAIN_TABLE_KEY_DERIVATION_INFO,
                    );
                    entry_table_value
                        .next_chain_table_uid::<BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(kwi_uid);
                })
                .or_insert_with(|| {
                    EntryTableValue::new::<BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                        rng,
                        keyword.hash(),
                    )
                });

            // Compute `Kwi_uid` if it has not already been computed.
            let (kwi_uid, kwi_value) = key_cache
                .get_entry_or_insert(&entry_table_value.kwi, CHAIN_TABLE_KEY_DERIVATION_INFO);

            // Add new indexed values to the chain.
            for indexed_value in indexed_values {
                entry_table_value.upsert_indexed_value::<
                    BLOCK_LENGTH,
                    TABLE_WIDTH,
                    KMAC_KEY_LENGTH,
                    DEM_KEY_LENGTH,
                    KmacKey,
                    DemScheme
                >(indexed_value, kwi_uid, kwi_value, new_chain_table_entries, rng)?;
            }
        }

        Ok(chain_table_additions)
    }
}

#[cfg(test)]
mod tests {

    use cosmian_crypto_core::{
        bytes_ser_de::Serializable,
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key, Dem},
        CsRng,
    };
    use rand::RngCore;

    use super::*;
    use crate::core::{structs::Location, Keyword, ENTRY_TABLE_KEY_DERIVATION_INFO};

    const MASTER_KEY_LENGTH: usize = 16;
    const UID_LENGTH: usize = 32;
    const KWI_LENGTH: usize = 16;
    const KMAC_KEY_LENGTH: usize = 32;
    const BLOCK_LENGTH: usize = 32;
    const TABLE_WIDTH: usize = 2;
    type KmacKey = Key<KMAC_KEY_LENGTH>;

    #[test]
    fn test_encryption() {
        let mut rng = CsRng::from_entropy();
        let k = KeyingMaterial::<MASTER_KEY_LENGTH>::new(&mut rng);
        let k_value = k.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let keyword = Keyword::from("Robert".as_bytes());

        let entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            KmacKey,
        >(&mut rng, keyword.hash());

        let c = entry_table_value
            .encrypt::<BLOCK_LENGTH, { Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
                &k_value, &mut rng,
            )
            .unwrap();

        let res = EntryTableValue::decrypt::<
            BLOCK_LENGTH,
            { Aes256GcmCrypto::KEY_LENGTH },
            Aes256GcmCrypto,
        >(&k_value, &c)
        .unwrap();

        assert_eq!(entry_table_value, res);
    }

    #[test]
    fn test_upsert_many_values() {
        let mut rng = CsRng::from_entropy();

        let keyword = Keyword::from("Robert".as_bytes());

        let mut entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            KmacKey,
        >(&mut rng, keyword.hash());

        let kwi_uid = entry_table_value
            .kwi
            .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
        let kwi_value = entry_table_value
            .kwi
            .derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        // Upsert TABLE_WIDTH + 1 values.
        let mut chain_table = EncryptedTable::default();
        for i in 0..=TABLE_WIDTH {
            let location = Location::from(format!("Robert's location nb {i}").as_bytes());
            let indexed_value = IndexedValue::from(location);

            entry_table_value.upsert_indexed_value::<
                BLOCK_LENGTH,
                TABLE_WIDTH,
                KMAC_KEY_LENGTH,
                {Aes256GcmCrypto::KEY_LENGTH},
                KmacKey,
                Aes256GcmCrypto
            >(&indexed_value, &kwi_uid, &kwi_value, &mut chain_table, &mut rng).unwrap();
        }

        let mut kwi_chain_table_uids = KwiChainUids::default();
        entry_table_value.unchain::<BLOCK_LENGTH, KMAC_KEY_LENGTH, {Aes256GcmCrypto::KEY_LENGTH}, KmacKey, Aes256GcmCrypto>(usize::MAX, &mut kwi_chain_table_uids);

        assert_eq!(kwi_chain_table_uids.len(), 1);

        // Recover the indexed values from the chain.
        let blocks: Vec<Block<BLOCK_LENGTH>> = kwi_chain_table_uids[&entry_table_value.kwi]
            .iter()
            .filter_map(|uid| chain_table.get(uid))
            .flat_map(|encrypted_chain_table_value| {
                ChainTableValue::<BLOCK_LENGTH>::decrypt::<
                    TABLE_WIDTH,
                    { Aes256GcmCrypto::KEY_LENGTH },
                    Aes256GcmCrypto,
                >(&kwi_value, encrypted_chain_table_value)
                .unwrap()
            })
            .collect();

        let bytes = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();

        let indexed_values = bytes
            .into_iter()
            .map(|bytes| IndexedValue::try_from_bytes(&bytes).unwrap());

        assert_eq!(indexed_values.len(), TABLE_WIDTH + 1);

        for (i, indexed_value) in indexed_values.enumerate() {
            assert!(indexed_value.is_location());
            assert_eq!(
                indexed_value,
                IndexedValue::from(Location::from(
                    format!("Robert's location nb {i}").as_bytes()
                ))
            );
        }
    }

    #[test]
    fn test_upsert_long_value() {
        let mut rng = CsRng::from_entropy();

        // Location which length is not a multiple of `BLOCK_LENGTH`
        let mut long_location = [0; 75];
        rng.fill_bytes(&mut long_location);
        let long_location = IndexedValue::from(Location::from(long_location.as_slice()));

        let mut long_keyword = [0; 47];
        rng.fill_bytes(&mut long_keyword);
        let long_keyword = Keyword::from(long_keyword.as_slice());

        let mut entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            KmacKey,
        >(&mut rng, long_keyword.hash());

        let kwi_uid = entry_table_value
            .kwi
            .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
        let kwi_value = entry_table_value
            .kwi
            .derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        let mut chain_table = EncryptedTable::default();
        entry_table_value.upsert_indexed_value::<
                BLOCK_LENGTH,
                TABLE_WIDTH,
                KMAC_KEY_LENGTH,
                {Aes256GcmCrypto::KEY_LENGTH},
                KmacKey,
                Aes256GcmCrypto
            >(&long_location, &kwi_uid, &kwi_value, &mut chain_table, &mut rng).unwrap();

        let mut kwi_chain_table_uids = KwiChainUids::default();
        entry_table_value.unchain::<BLOCK_LENGTH, KMAC_KEY_LENGTH, {Aes256GcmCrypto::KEY_LENGTH}, KmacKey, Aes256GcmCrypto>(usize::MAX, &mut kwi_chain_table_uids);

        // Only one keyword is indexed.
        assert_eq!(kwi_chain_table_uids.len(), 1);

        // Recover the indexed values from the chain.
        let blocks: Vec<Block<BLOCK_LENGTH>> = kwi_chain_table_uids[&entry_table_value.kwi]
            .iter()
            .filter_map(|uid| chain_table.get(uid))
            .flat_map(|encrypted_chain_table_value| {
                ChainTableValue::<BLOCK_LENGTH>::decrypt::<
                    TABLE_WIDTH,
                    { Aes256GcmCrypto::KEY_LENGTH },
                    Aes256GcmCrypto,
                >(&kwi_value, encrypted_chain_table_value)
                .unwrap()
            })
            .collect();

        let bytes = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();

        let indexed_values = bytes
            .into_iter()
            .map(|bytes| IndexedValue::try_from_bytes(&bytes).unwrap());

        assert_eq!(indexed_values.len(), 1);

        for indexed_value in indexed_values {
            assert!(indexed_value.is_location());
            assert_eq!(indexed_value, long_location);
        }
    }
}
