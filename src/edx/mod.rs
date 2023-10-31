//! A Dictionary Encryption Scheme securely stores constant length values inside
//! an Encrypted Dictionary (EDX).

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
};

use async_trait::async_trait;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use zeroize::ZeroizeOnDrop;

pub mod chain_table;
pub mod entry_table;
mod structs;

pub use structs::{
    EncryptedValue, Seed, Token, TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens,
};

use crate::{CallbackErrorTrait, Label};

#[async_trait(?Send)]
pub trait TokenDump {
    type Error;

    async fn dump_tokens(&self) -> Result<HashSet<Token>, Self::Error>;
}

#[async_trait(?Send)]
pub trait DxEnc<const VALUE_LENGTH: usize> {
    /// Seed used to derive the key.
    type Seed: Sized + ZeroizeOnDrop + AsRef<[u8]> + Default + AsMut<[u8]>;

    /// Cryptographically secure key.
    type Key: Sized + ZeroizeOnDrop;

    /// Type of error returned by the scheme.
    type Error: std::error::Error;

    /// Fixed length encrypted value stored inside the encrypted dictionary.
    type EncryptedValue: Debug + Sized + Clone;

    /// Backend storage.
    type Store: EdxStore<VALUE_LENGTH>;

    /// Instantiates a new Dx-Enc scheme.
    fn setup(edx: Self::Store) -> Self;

    /// Generates a new random seed.
    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed;

    /// Deterministically derives a cryptographic key from the given seed.
    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key;

    /// Deterministically transforms the given bytes into a cryptographically
    /// secure token using the given key.
    fn tokenize(&self, key: &Self::Key, bytes: &[u8], label: Option<&Label>) -> Token;

    /// Queries the given tokens and returns the encrypted values.
    async fn get(
        &self,
        tokens: HashSet<Token>,
    ) -> Result<Vec<(Token, Self::EncryptedValue)>, Self::Error>;

    /// Decrypts the given encrypted value with the given key.
    fn resolve(
        &self,
        key: &Self::Key,
        encrypted_value: &Self::EncryptedValue,
    ) -> Result<[u8; VALUE_LENGTH], Self::Error>;

    /// Encrypts the given values using the given key.
    fn prepare(
        &self,
        rng: &mut impl CryptoRngCore,
        key: &Self::Key,
        values: [u8; VALUE_LENGTH],
    ) -> Result<Self::EncryptedValue, Self::Error>;

    /// Conditionally upsert the given items into the EDX.
    ///
    /// For each new token:
    /// 1. if there is no old value and no EDX value, inserts the new value;
    /// 2. if the old value is equal to the EDX value, updates the EDX value
    /// with the new value;
    /// 3. if the old value is different from the EDX value, returns the EDX
    /// value;
    ///
    /// A summary of the different cases is presented in the following table:
    ///
    /// +--------------+----------+-----------+-----------+
    /// | stored \ old | None     | Some("A") | Some("B") |
    /// +--------------+----------+-----------+-----------+
    /// | None         | upserted | rejected  | rejected  |
    /// | Some("A")    | rejected | upserted  | rejected  |
    /// | Some("B")    | rejected | rejected  | upserted  |
    /// +--------------+----------+-----------+-----------+
    ///
    /// All modifications to the EDX are *atomic*.
    async fn upsert(
        &self,
        old_values: HashMap<Token, Self::EncryptedValue>,
        new_values: HashMap<Token, Self::EncryptedValue>,
    ) -> Result<HashMap<Token, Self::EncryptedValue>, Self::Error>;

    /// Inserts the given items into the EDX.
    ///
    /// # Error
    ///
    /// Returns an error without inserting any value if the EDX already contains
    /// a value for a given tokens.
    async fn insert(&self, values: HashMap<Token, Self::EncryptedValue>)
        -> Result<(), Self::Error>;

    /// Deletes the given items from the EDX.
    async fn delete(&self, tokens: HashSet<Token>) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
pub trait EdxStore<const VALUE_LENGTH: usize> {
    /// Type of error returned by the EDX.
    type Error: CallbackErrorTrait;

    /// Queries the EDX for all tokens stored.
    async fn dump_tokens(&self) -> Result<Tokens, Self::Error>;

    /// Queries an Edx for the given tokens. Only returns a value for the tokens
    /// that are present in the store.
    async fn fetch(
        &self,
        tokens: Tokens,
    ) -> Result<TokenWithEncryptedValueList<VALUE_LENGTH>, Self::Error>;

    /// Upserts the given values into the Edx for the given tokens.
    ///
    /// The upsert operation should be *atomic* and *conditional*.
    ///
    /// For each token:
    /// 1. if there is no old value and no stored value, inserts the new value;
    /// 2. if the old value is equal to the stored value, updates the stored
    /// value with the new value;
    /// 3. if the old value is different from the stored value returns the
    /// stored value;
    ///
    /// A summary of the different cases is presented in the following table:
    ///
    /// +--------------+----------+-----------+-----------+
    /// | stored \ old | None     | Some("A") | Some("B") |
    /// +--------------+----------+-----------+-----------+
    /// | None         | upserted | rejected  | rejected  |
    /// | Some("A")    | rejected | upserted  | rejected  |
    /// | Some("B")    | rejected | rejected  | upserted  |
    /// +--------------+----------+-----------+-----------+
    async fn upsert(
        &self,
        old_values: TokenToEncryptedValueMap<VALUE_LENGTH>,
        new_values: TokenToEncryptedValueMap<VALUE_LENGTH>,
    ) -> Result<TokenToEncryptedValueMap<VALUE_LENGTH>, Self::Error>;

    /// Inserts the given values into the Edx for the given tokens.
    ///
    /// # Error
    ///
    /// If a value is already stored for one of these tokens, no new value
    /// should be inserted and an error should be returned.
    async fn insert(
        &self,
        values: TokenToEncryptedValueMap<VALUE_LENGTH>,
    ) -> Result<(), Self::Error>;

    /// Deletes the lines associated to the given tokens from the EDX.
    async fn delete(&self, tokens: Tokens) -> Result<(), Self::Error>;
}

#[cfg(any(test, feature = "in_memory"))]
pub mod in_memory {
    use std::{
        collections::HashMap,
        fmt::{Debug, Display},
        ops::Deref,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use cosmian_crypto_core::CryptoCoreError;
    #[cfg(feature = "in_memory")]
    use cosmian_crypto_core::{bytes_ser_de::Serializable, Nonce};

    use super::{EdxStore, Token, TokenToEncryptedValueMap, TokenWithEncryptedValueList, Tokens};
    #[cfg(feature = "in_memory")]
    use crate::parameters::{MAC_LENGTH, NONCE_LENGTH};
    use crate::{error::CallbackErrorTrait, EncryptedValue};

    #[derive(Debug)]
    pub struct KvStoreError(String);

    impl From<CryptoCoreError> for KvStoreError {
        fn from(value: CryptoCoreError) -> Self {
            Self(value.to_string())
        }
    }

    impl Display for KvStoreError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "callback error")
        }
    }

    impl std::error::Error for KvStoreError {}
    impl CallbackErrorTrait for KvStoreError {}

    #[derive(Debug)]
    pub struct InMemoryEdx<const VALUE_LENGTH: usize>(
        Arc<Mutex<TokenToEncryptedValueMap<VALUE_LENGTH>>>,
    );

    impl<const VALUE_LENGTH: usize> Deref for InMemoryEdx<VALUE_LENGTH> {
        type Target = Arc<Mutex<TokenToEncryptedValueMap<VALUE_LENGTH>>>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<const VALUE_LENGTH: usize> Default for InMemoryEdx<VALUE_LENGTH> {
        fn default() -> Self {
            Self(Default::default())
        }
    }

    impl<const VALUE_LENGTH: usize> InMemoryEdx<VALUE_LENGTH> {
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.lock().expect("could not lock mutex").is_empty()
        }

        #[must_use]
        pub fn len(&self) -> usize {
            self.lock().expect("could not lock mutex").len()
        }

        #[must_use]
        pub fn size(&self) -> usize {
            self.len() * (Token::LENGTH + EncryptedValue::<VALUE_LENGTH>::LENGTH)
        }

        pub fn flush(&mut self) {
            *self.lock().expect("could not lock mutex") = TokenToEncryptedValueMap::default();
        }

        pub fn load(&mut self, table: TokenToEncryptedValueMap<VALUE_LENGTH>) {
            *self.lock().expect("could not lock mutex") = table;
        }
    }

    #[cfg(feature = "in_memory")]
    impl<const VALUE_LENGTH: usize> Serializable for InMemoryEdx<VALUE_LENGTH> {
        type Error = KvStoreError;

        fn length(&self) -> usize {
            (self.lock().expect("could not lock mutex").deref()).len()
                * (Token::LENGTH + NONCE_LENGTH + MAC_LENGTH + VALUE_LENGTH)
        }

        fn write(
            &self,
            ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
        ) -> Result<usize, Self::Error> {
            let table = &*self.lock().expect("could not lock mutex");
            let mut n = ser.write_leb128_u64(table.len() as u64)?;
            for (k, v) in table.iter() {
                n += ser.write_array(k)?;
                n += ser.write_array(&v.nonce.0)?;
                n += ser.write_array(&v.ciphertext)?;
                n += ser.write_array(&v.tag)?;
            }
            Ok(n)
        }

        fn read(
            de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
        ) -> Result<Self, Self::Error> {
            let n = de.read_leb128_u64()? as usize;
            let mut table = HashMap::with_capacity(n);
            for _ in 0..n {
                let k = de.read_array::<{ Token::LENGTH }>()?;
                // previous version used to write the size of the value.
                let _ = de.read_leb128_u64();
                let nonce = Nonce::from(de.read_array::<NONCE_LENGTH>()?);
                let ciphertext = de.read_array::<VALUE_LENGTH>()?;
                let tag = de.read_array::<MAC_LENGTH>()?;
                table.insert(
                    Token::from(k),
                    EncryptedValue {
                        ciphertext,
                        tag,
                        nonce,
                    },
                );
            }

            Ok(Self(Arc::new(Mutex::new(TokenToEncryptedValueMap::from(
                table,
            )))))
        }
    }

    #[async_trait(?Send)]
    impl<const VALUE_LENGTH: usize> EdxStore<VALUE_LENGTH> for InMemoryEdx<VALUE_LENGTH> {
        type Error = KvStoreError;

        async fn dump_tokens(&self) -> Result<Tokens, Self::Error> {
            Ok(self
                .lock()
                .expect("could not lock table")
                .keys()
                .copied()
                .collect())
        }

        async fn fetch(
            &self,
            tokens: Tokens,
        ) -> Result<TokenWithEncryptedValueList<VALUE_LENGTH>, KvStoreError> {
            Ok(TokenWithEncryptedValueList::from(
                tokens
                    .into_iter()
                    .filter_map(|uid| {
                        self.lock()
                            .expect("couldn't lock the table")
                            .get(&uid)
                            .cloned()
                            .map(|v| (uid, v))
                    })
                    .collect::<Vec<_>>(),
            ))
        }

        async fn upsert(
            &self,
            old_values: TokenToEncryptedValueMap<VALUE_LENGTH>,
            new_values: TokenToEncryptedValueMap<VALUE_LENGTH>,
        ) -> Result<TokenToEncryptedValueMap<VALUE_LENGTH>, KvStoreError> {
            let edx = &mut self.lock().expect("couldn't lock the table");
            // Ensures an value is present inside the EDX for each given old value.
            if old_values.keys().any(|token| !edx.contains_key(token)) {
                return Err(KvStoreError(format!(
                    "missing EDX tokens {:?}",
                    old_values
                        .keys()
                        .filter(|token| !edx.contains_key(*token))
                        .collect::<Vec<_>>()
                )));
            }

            let mut res = HashMap::new();
            for (token, new_ciphertext) in new_values.into_iter() {
                let old_ciphertext = old_values.get(&token);
                let edx_ciphertext = edx.get(&token);

                if old_ciphertext == edx_ciphertext {
                    edx.insert(token, new_ciphertext.clone());
                } else {
                    res.insert(
                        token,
                        edx_ciphertext
                            .cloned()
                            .expect("above check ensures this cannot happen"),
                    );
                }
            }

            Ok(TokenToEncryptedValueMap::from(res))
        }

        async fn insert(
            &self,
            items: TokenToEncryptedValueMap<VALUE_LENGTH>,
        ) -> Result<(), Self::Error> {
            let edx = &mut self.lock().expect("couldn't lock the table");

            if items.keys().any(|token| edx.contains_key(token)) {
                return Err(KvStoreError(format!(
                    "cannot insert value for used tokens ({:?})",
                    items
                        .keys()
                        .filter(|token| edx.contains_key(*token))
                        .collect::<Vec<_>>()
                )));
            }

            edx.extend(items);

            Ok(())
        }

        async fn delete(&self, items: Tokens) -> Result<(), Self::Error> {
            let edx = &mut self.lock().expect("could not lock mutex");
            for token in &*items {
                edx.remove(token);
            }
            Ok(())
        }
    }
}
