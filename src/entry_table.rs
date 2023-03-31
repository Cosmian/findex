//! Defines all structures and methods specific to the Entry Table.
//!
//! The Entry Table indexes chains of values stored in the Chain Table. Each
//! chain is associated to a keyword and is indexed by a unique item in the
//! Entry Table. The UID of this item is obtained by deriving the hash of the
//! associated keyword.

use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializer},
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, SymKey},
};

use crate::{
    chain_table::{ChainTable, ChainTableValue, KwiChainUids},
    error::CoreError as Error,
    structs::{BlockType, EncryptedTable, IndexedValue, KeywordHash, Label, Uid},
    KeyingMaterial, Keyword, CHAIN_TABLE_KEY_DERIVATION_INFO,
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
    pub(crate) chain_table_uid: Option<Uid<UID_LENGTH>>,
    pub(crate) kwi: KeyingMaterial<KWI_LENGTH>,
    pub(crate) keyword_hash: [u8; Keyword::HASH_LENGTH],
}

impl<const UID_LENGTH: usize, const KWI_LENGTH: usize> EntryTableValue<UID_LENGTH, KWI_LENGTH> {
    /// Creates a new Entry Table value for the keyword which hash is given.
    ///
    /// - `rng`             : random number generator
    /// - `keyword_hash`    : hash of the indexing keyword
    pub(crate) fn new<const CHAIN_TABLE_WITH: usize, const BLOCK_LENGTH: usize>(
        rng: &mut impl CryptoRngCore,
        keyword_hash: [u8; Keyword::HASH_LENGTH],
    ) -> Self {
        let kwi = KeyingMaterial::new(rng);
        Self {
            chain_table_uid: None,
            kwi,
            keyword_hash,
        }
    }

    /// Computes the next UID of the indexed chain. Updates the Entry Table
    /// value and returns this UID.
    ///
    /// - `kwi_uid` : KMAC key used to generate Chain Table UIDs.
    pub(crate) fn next_chain_table_uid<
        const CHAIN_TABLE_WITH: usize,
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
    >(
        &mut self,
        kwi_uid: &KmacKey,
    ) -> &Uid<UID_LENGTH> {
        let new_uid = match &self.chain_table_uid {
            Some(old_uid) => {
                ChainTable::<UID_LENGTH, CHAIN_TABLE_WITH, BLOCK_LENGTH>::generate_uid(
                    kwi_uid, old_uid,
                )
            }
            None => ChainTable::<UID_LENGTH, CHAIN_TABLE_WITH, BLOCK_LENGTH>::generate_uid(
                kwi_uid,
                &self.keyword_hash,
            ),
        };

        self.chain_table_uid = Some(new_uid);
        self.chain_table_uid.as_ref().unwrap()
    }

    ///// TODO (TBZ): document better
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
        const CHAIN_TABLE_WIDTH: usize,
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
    >(
        &mut self,
        insertion_type: BlockType,
        indexed_value: &IndexedValue,
        kwi_uid: &KmacKey,
        chain_table: &mut ChainTable<UID_LENGTH, CHAIN_TABLE_WIDTH, BLOCK_LENGTH>,
    ) -> Result<(), Error> {
        // Blocks to add to the Chain Table.
        let new_blocks = indexed_value.to_blocks(insertion_type)?;
        let mut index = 0;

        // Fill the last Chain Table line if it is given.
        if let Some(chain_table_uid) = &self.chain_table_uid {
            if let Some(chain_table_value) = chain_table.get_mut(chain_table_uid) {
                // Number of blocks to add to the last Chain Table line.
                // It cannot be greater than:
                // - the remaining slots in the line;
                // - the remaining number of blocks.
                let n_additions = (CHAIN_TABLE_WIDTH - chain_table_value.as_blocks().len())
                    .min(new_blocks.len() - index);
                for _ in 0..n_additions {
                    chain_table_value.try_push(new_blocks[index])?;
                    index += 1;
                }
            }
        }

        // Add remaining blocks to new lines until exhaustion.
        while index < new_blocks.len() {
            let n_additions = CHAIN_TABLE_WIDTH.min(new_blocks.len() - index);
            let new_chain_uid = self
                .next_chain_table_uid::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                    kwi_uid,
                );
            let mut new_chain_value = ChainTableValue::default();
            for _ in 0..n_additions {
                new_chain_value.try_push(new_blocks[index])?;
                index += 1;
            }
            let old_value = chain_table.insert(new_chain_uid.clone(), new_chain_value);
            if old_value.is_some() {
                return Err(Error::CryptoError(format!(
                    "conflit when inserting Chain Table value for UID {new_chain_uid:?}"
                )));
            }
        }

        Ok(())
    }

    /// Encrypts the `EntryTableValue` using the given `𝐾_value`.
    ///
    /// - `k_value` : `𝐾_value`
    /// - `rng`     : random number generator
    pub(crate) fn encrypt<const DEM_KEY_LENGTH: usize, DemScheme: Dem<DEM_KEY_LENGTH>>(
        &self,
        k_value: &DemScheme::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut ser = Serializer::new();
        if let Some(chain_table_uid) = &self.chain_table_uid {
            ser.write_array(chain_table_uid)?;
        } else {
            ser.write_array(&[0; UID_LENGTH])?;
        }
        ser.write_array(&self.kwi)?;
        ser.write_array(&self.keyword_hash)?;
        DemScheme::encrypt(rng, k_value, &ser.finalize(), None).map_err(Error::from)
    }

    /// Decrypts an encrypted `EntryTableValue` using the given `𝐾_value`.
    ///
    /// - `k_value`     : `K_value`
    /// - `ciphertext`  : encrypted entry table value
    pub(crate) fn decrypt<const DEM_KEY_LENGTH: usize, DemScheme: Dem<DEM_KEY_LENGTH>>(
        k_value: &DemScheme::Key,
        ciphertext: &[u8],
    ) -> Result<Self, Error> {
        let bytes = DemScheme::decrypt(k_value, ciphertext, None)?;
        let mut de = Deserializer::new(&bytes);

        let chain_table_uid = de.read_array::<UID_LENGTH>()?;
        let kwi = de.read_array::<KWI_LENGTH>()?;
        let keyword_hash = de.read_array::<{ Keyword::HASH_LENGTH }>()?;

        let chain_table_uid = if [0; UID_LENGTH] == chain_table_uid {
            None
        } else {
            Some(chain_table_uid.into())
        };

        Ok(Self {
            chain_table_uid,
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
        const CHAIN_TABLE_WIDTH: usize,
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
        let entry = kwi_chain_table_uids
            .entry(self.kwi.clone())
            .or_insert_with(Vec::new);

        if self.chain_table_uid.is_none() {
            return;
        }

        let kwi_uid: KmacKey = self.kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        // Derive the Chain Table UID.
        let mut current_chain_table_uid =
            ChainTable::<UID_LENGTH, CHAIN_TABLE_WIDTH, BLOCK_LENGTH>::generate_uid(
                &kwi_uid,
                &self.keyword_hash,
            );

        for _ in 0..max_results {
            // Add the new Chain Table UID to the map.
            entry.push(current_chain_table_uid.clone());

            // Return if we found the UID stored in the Entry Table value.
            if Some(&current_chain_table_uid) == self.chain_table_uid.as_ref() {
                break;
            }

            // Compute the next UID.
            current_chain_table_uid =
                ChainTable::<UID_LENGTH, CHAIN_TABLE_WIDTH, BLOCK_LENGTH>::generate_uid(
                    &kwi_uid,
                    &current_chain_table_uid,
                );
        }
    }
}

/// Findex Entry Table.
///
/// This is a key value store. The value needs to be encrypted in order to
/// secure it (cf [`EncryptedTable`](structs::EncryptedTable)).
///
/// +-----------+-----------------------------------+
/// | Key       | Value                             |
/// +-----------+-------+-------+-------------------+
/// | UID       | K_wi  | H_wi  | Option<UID_last>  |
/// +-----------+-------+-------+-------------------+
///
/// with:
/// - `UID_LENGTH` is the length of `UID` and `UID_last`
/// - `KWI_LENGTH` is the length of `K_wi`
/// - `K_wi` is the ephemeral key associated to the chain of the keyword `w_i`
/// - `H_wi` is the hash of the keyword `w_i`; its length is
///   [`Keyword::HASH_LENGTH`](Keyword::HASH_LENGTH)
/// - `UID_last` is the UID of the last Chain Table line used to store the chain
///   of the keyword `w_i`; it is optional in the Entry Table since the line
///   assocated to a keyword can link to no Chain Table line after a compact
///   operation deleted all values indexed for this keyword (Entry Table lines
///   with no `UID_last` are removed during reindexation).
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
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Generates an `EntryTableUid` from the given hash value, KMAC key and
    /// label. The hash value given *should* be the one of the indexing keyword.
    ///
    /// - `key`             : KMAC key
    /// - `keyword_hash`    : hash of the `Keyword`
    /// - `label`           : additional public information
    pub fn generate_uid<const KMAC_KEY_LENGTH: usize, KmacKey: SymKey<KMAC_KEY_LENGTH>>(
        key: &KmacKey,
        keyword_hash: &KeywordHash,
        label: &Label,
    ) -> Uid<UID_LENGTH> {
        kmac!(UID_LENGTH, key.as_bytes(), keyword_hash, label).into()
    }

    /// Decrypts an Entry Table with the given `K_value`.
    ///
    /// - `k_value`                 : DEM key
    /// - `encrypted_entry_table`   : encrypted Entry Table
    pub fn decrypt<const DEM_KEY_LENGTH: usize, DemScheme: Dem<DEM_KEY_LENGTH>>(
        k_value: &DemScheme::Key,
        encrypted_entry_table: &EncryptedTable<UID_LENGTH>,
    ) -> Result<Self, Error> {
        let mut entry_table = Self::with_capacity(encrypted_entry_table.len());
        for (k, v) in encrypted_entry_table.iter() {
            let decrypted_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::decrypt::<
                DEM_KEY_LENGTH,
                DemScheme,
            >(k_value, v)
            .map_err(|_| {
                Error::CryptoError(format!(
                    "fail to decrypt one of the `value` returned by the fetch entries callback \
                     (uid was '{k:?}', value was {})",
                    if v.is_empty() {
                        "empty".to_owned()
                    } else {
                        format!("'{v:?}'")
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
    pub fn encrypt<const DEM_KEY_LENGTH: usize, DemScheme: Dem<DEM_KEY_LENGTH>>(
        &self,
        k_value: &DemScheme::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<EncryptedTable<UID_LENGTH>, Error> {
        let mut encrypted_entry_table = EncryptedTable::with_capacity(self.len());
        for (k, v) in self.iter() {
            encrypted_entry_table.insert(
                k.clone(),
                EntryTableValue::<UID_LENGTH, KWI_LENGTH>::encrypt::<DEM_KEY_LENGTH, DemScheme>(
                    v, k_value, rng,
                )?,
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
        const CHAIN_TABLE_WITH: usize,
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
                value.unchain::<CHAIN_TABLE_WITH, BLOCK_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
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
    ///
    /// Creates new Entry Table lines for UIDs (derived from the keywords) that
    /// do not already exist. Creates the new encrypted lines to add to the
    /// Chain Table in order to index the given values.
    ///
    /// Returns a map of the upserted Entry Table items to their associated
    /// chain.
    ///
    /// # Parameters
    ///
    /// - `rng`                 : random number generator
    /// - `new_chain_elements`  : map values to their indexing keywords
    pub fn upsert<
        const CHAIN_TABLE_WIDTH: usize,
        const BLOCK_LENGTH: usize,
        const KMAC_KEY_LENGTH: usize,
        const DEM_KEY_LENGTH: usize,
        KmacKey: SymKey<KMAC_KEY_LENGTH>,
        DemScheme: Dem<DEM_KEY_LENGTH>,
    >(
        &mut self,
        rng: &mut impl CryptoRngCore,
        new_chain_elements: &HashMap<
            Uid<UID_LENGTH>,
            (KeywordHash, HashMap<IndexedValue, BlockType>),
        >,
    ) -> Result<HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>, Error> {
        let mut chain_table_additions = HashMap::with_capacity(new_chain_elements.len());
        for (entry_table_uid, (keyword_hash, indexed_values)) in new_chain_elements {
            let entry_table_value = self.entry(entry_table_uid.clone()).or_insert_with(|| {
                EntryTableValue::new::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>(rng, *keyword_hash)
            });

            let kwi_uid = entry_table_value
                .kwi
                .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let kwi_value = entry_table_value
                .kwi
                .derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

            // It is only possible to insert new entries in the Chain Table. Do not fetch
            // last Chain Table line for the given keyword but start a new line.
            let mut new_chain_table_entries = ChainTable::default();

            for (indexed_value, block_type) in indexed_values {
                entry_table_value.upsert_indexed_value::<
                    CHAIN_TABLE_WIDTH,
                    BLOCK_LENGTH,
                    KMAC_KEY_LENGTH,
                    KmacKey,
                >(*block_type, indexed_value, &kwi_uid, &mut new_chain_table_entries)?;
            }

            let encrypted_chain_table_additions = new_chain_table_entries
                .into_iter()
                .map(|(uid, value)| -> Result<_, _> {
                    Ok((
                        uid,
                        value.encrypt::<DEM_KEY_LENGTH, DemScheme>(&kwi_value, rng)?,
                    ))
                })
                .collect::<Result<_, Error>>()?;

            chain_table_additions.insert(entry_table_uid.clone(), encrypted_chain_table_additions);
        }

        Ok(chain_table_additions)
    }
}

#[cfg(test)]
mod tests {

    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
        CsRng,
    };

    use super::*;
    use crate::{parameters::*, structs::Location, Keyword, ENTRY_TABLE_KEY_DERIVATION_INFO};

    #[test]
    fn test_encryption() {
        let mut rng = CsRng::from_entropy();
        let k = KeyingMaterial::<MASTER_KEY_LENGTH>::new(&mut rng);
        let k_value = k.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let keyword = Keyword::from("Robert".as_bytes());

        let mut entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
        >(&mut rng, keyword.hash());

        let c = entry_table_value
            .encrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(&k_value, &mut rng)
            .unwrap();

        let res = EntryTableValue::decrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
            &k_value, &c,
        )
        .unwrap();

        assert_eq!(entry_table_value, res);

        let kwi_uid = entry_table_value
            .kwi
            .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
        entry_table_value
            .next_chain_table_uid::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                &kwi_uid,
            );

        let c = entry_table_value
            .encrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(&k_value, &mut rng)
            .unwrap();

        let res = EntryTableValue::decrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
            &k_value, &c,
        )
        .unwrap();

        assert_eq!(entry_table_value, res);
    }

    #[test]
    fn test_upsert_many_values() {
        let mut rng = CsRng::from_entropy();
        let keyword = Keyword::from("Robert".as_bytes());

        let mut entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
        >(&mut rng, keyword.hash());

        let kwi_uid = entry_table_value
            .kwi
            .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        // Upsert TABLE_WIDTH + 1 values.
        let mut chain_table = ChainTable::default();
        for i in 0..(CHAIN_TABLE_WIDTH + 1) {
            let location = Location::from(format!("Robert's location nb {i}").as_bytes());
            let indexed_value = IndexedValue::from(location);

            entry_table_value
                .upsert_indexed_value::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                    BlockType::Addition,
                    &indexed_value,
                    &kwi_uid,
                    &mut chain_table,
                )
                .unwrap();
        }

        // Recover Chain Table UIDs associated to the Entry Table value.
        let mut kwi_chain_table_uids = KwiChainUids::default();
        entry_table_value.unchain::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            {Aes256GcmCrypto::KEY_LENGTH},
            KmacKey,
            Aes256GcmCrypto
        >(usize::MAX, &mut kwi_chain_table_uids);

        assert_eq!(kwi_chain_table_uids.len(), 1);

        // Recover the indexed values from the Chain Table blocks.
        let blocks = kwi_chain_table_uids[&entry_table_value.kwi]
            .iter()
            .filter_map(|uid| chain_table.get(uid))
            .flat_map(|chain_table_value| chain_table_value.as_blocks());
        let indexed_values = IndexedValue::from_blocks(blocks).unwrap();

        // Assert the correct indexed values have been recovered.
        assert_eq!(indexed_values.len(), CHAIN_TABLE_WIDTH + 1);
        for i in 0..=CHAIN_TABLE_WIDTH {
            assert!(indexed_values.contains(&IndexedValue::from(Location::from(
                format!("Robert's location nb {i}").as_bytes()
            ))));
        }

        // Delete all indexed values except the first one.
        for i in 1..=CHAIN_TABLE_WIDTH {
            let location = Location::from(format!("Robert's location nb {i}").as_bytes());
            let indexed_value = IndexedValue::from(location);
            entry_table_value
                .upsert_indexed_value::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                    BlockType::Deletion,
                    &indexed_value,
                    &kwi_uid,
                    &mut chain_table,
                )
                .unwrap();
        }

        // Recover Chain Table UIDs associated to the Entry Table value.
        let mut kwi_chain_table_uids = KwiChainUids::default();
        entry_table_value.unchain::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            {Aes256GcmCrypto::KEY_LENGTH},
            KmacKey,
            Aes256GcmCrypto
        >(usize::MAX, &mut kwi_chain_table_uids);

        assert_eq!(kwi_chain_table_uids.len(), 1);

        // Recover the indexed values from the Chain Table blocks.
        let blocks = kwi_chain_table_uids[&entry_table_value.kwi]
            .iter()
            .filter_map(|uid| chain_table.get(uid))
            .flat_map(|chain_table_value| chain_table_value.as_blocks());
        let indexed_values = IndexedValue::from_blocks(blocks).unwrap();

        // Assert the correct indexed values have been recovered.
        assert_eq!(indexed_values.len(), 1);
        assert!(indexed_values.contains(&IndexedValue::from(Location::from(
            "Robert's location nb 0".as_bytes()
        ))));
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
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
        >(&mut rng, long_keyword.hash());

        let kwi_uid = entry_table_value
            .kwi
            .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        let mut chain_table = ChainTable::default();
        entry_table_value
            .upsert_indexed_value::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, KmacKey>(
                BlockType::Addition,
                &long_location,
                &kwi_uid,
                &mut chain_table,
            )
            .unwrap();

        let mut kwi_chain_table_uids = KwiChainUids::default();
        entry_table_value.unchain::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            {Aes256GcmCrypto::KEY_LENGTH},
            KmacKey,
            Aes256GcmCrypto
        >(usize::MAX, &mut kwi_chain_table_uids);

        // Only one keyword is indexed.
        assert_eq!(kwi_chain_table_uids.len(), 1);

        // Recover the indexed values from the chain.
        let blocks = kwi_chain_table_uids[&entry_table_value.kwi]
            .iter()
            .filter_map(|uid| chain_table.get(uid))
            .flat_map(|chain_table_value| chain_table_value.as_blocks());

        let indexed_values = IndexedValue::from_blocks(blocks).unwrap();

        assert_eq!(indexed_values.len(), 1);

        for indexed_value in indexed_values {
            assert!(indexed_value.is_location());
            assert_eq!(indexed_value, long_location);
        }
    }
}
