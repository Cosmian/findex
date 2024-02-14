use async_trait::async_trait;

use crate::{
    dx_enc::{Edx, TokenSet},
    DbInterfaceErrorTrait,
};

// TODO: add `connect`/`setup` to the DX interface. First check if all existing
// interfaces allow it.
#[async_trait(?Send)]
pub trait DbInterface {
    /// Type of error returned by the EDX.
    type Error: DbInterfaceErrorTrait;

    /// Queries an Edx for the given tokens. Only returns a value for the tokens
    /// that are present in the store.
    async fn fetch(&self, tokens: TokenSet) -> Result<Edx, Self::Error>;

    /// Upserts the given values into the database for the given tokens.
    ///
    /// For each new token:
    /// 1. if there is no old value and no value stored, inserts the new value;
    /// 2. if there is an old value but no value stored, returns an error;
    /// 3. if the old value is equal to the value stored, updates the value stored
    /// with the new value;
    /// 4. else returns the value stored with its associated token.
    ///
    /// A summary of the different cases is presented in the following table:
    ///
    /// +--------------+----------+-----------+-----------+
    /// | stored \ old | None     | Some("A") | Some("B") |
    /// +--------------+----------+-----------+-----------+
    /// | None         | upserted | *error*   | *error*   |
    /// | Some("A")    | rejected | upserted  | rejected  |
    /// | Some("B")    | rejected | rejected  | upserted  |
    /// +--------------+----------+-----------+-----------+
    ///
    /// All modifications of the EDX should be *atomic*.
    async fn upsert(&self, old_values: Edx, new_values: Edx) -> Result<Edx, Self::Error>;

    /// Inserts the given values into the Edx for the given tokens.
    ///
    /// # Error
    ///
    /// If a value is already stored for one of these tokens, no new value
    /// should be inserted and an error should be returned.
    async fn insert(&self, values: Edx) -> Result<Edx, Self::Error>;

    /// Deletes the lines associated to the given tokens from the EDX.
    async fn delete(&self, tokens: TokenSet) -> Result<(), Self::Error>;

    /// Returns all data stored through this interface.
    async fn dump(&self) -> Result<Edx, Self::Error>;
}

#[cfg(any(test, feature = "in_memory"))]
pub mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fmt::{Debug, Display},
        ops::Deref,
        sync::{Arc, Mutex},
        thread::spawn,
    };

    use async_trait::async_trait;
    #[cfg(feature = "in_memory")]
    use cosmian_crypto_core::{bytes_ser_de::Serializable, Nonce};
    use cosmian_crypto_core::{CryptoCoreError, CsRng};
    use futures::executor::block_on;
    use rand::{RngCore, SeedableRng};

    use super::{DbInterface, Edx, TokenSet};
    #[cfg(feature = "in_memory")]
    use crate::parameters::{MAC_LENGTH, NONCE_LENGTH};
    use crate::{dx_enc::Token, error::DbInterfaceErrorTrait};

    #[derive(Debug)]
    pub struct InMemoryDbError(String);

    impl From<CryptoCoreError> for InMemoryDbError {
        fn from(value: CryptoCoreError) -> Self {
            Self(value.to_string())
        }
    }

    impl Display for InMemoryDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "callback error")
        }
    }

    impl std::error::Error for InMemoryDbError {}
    impl DbInterfaceErrorTrait for InMemoryDbError {}

    #[derive(Clone, Debug)]
    pub struct InMemoryDb(Arc<Mutex<Edx>>);

    impl Deref for InMemoryDb {
        type Target = Arc<Mutex<Edx>>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Default for InMemoryDb {
        fn default() -> Self {
            Self(Default::default())
        }
    }

    impl InMemoryDb {
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
            self.lock()
                .expect("poisoned lock")
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum()
        }

        pub fn flush(&mut self) {
            *self.lock().expect("could not lock mutex") = Edx::default();
        }

        pub fn load(&mut self, table: Edx) {
            *self.lock().expect("could not lock mutex") = table;
        }
    }

    #[cfg(feature = "in_memory")]
    impl<const VALUE_LENGTH: usize> Serializable for InMemoryDb<VALUE_LENGTH> {
        type Error = InMemoryDbError;

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

            Ok(Self(Arc::new(Mutex::new(Edx::from(table)))))
        }
    }

    #[async_trait(?Send)]
    impl DbInterface for InMemoryDb {
        type Error = InMemoryDbError;

        async fn delete(&self, items: TokenSet) -> Result<(), Self::Error> {
            let edx = &mut self.lock().expect("could not lock mutex");
            for token in &*items {
                edx.remove(token);
            }
            Ok(())
        }

        async fn dump(&self) -> Result<Edx, Self::Error> {
            Ok(self.lock().expect("could not lock table").clone())
        }

        async fn fetch(&self, tokens: TokenSet) -> Result<Edx, InMemoryDbError> {
            Ok(tokens
                .into_iter()
                .filter_map(|token| {
                    self.lock()
                        .expect("couldn't lock the table")
                        .get(&token)
                        .cloned()
                        .map(|v| (token, v))
                })
                .collect())
        }

        async fn insert(&self, items: Edx) -> Result<Edx, Self::Error> {
            let db = &mut *self.lock().expect("couldn't lock the table");
            let mut res = Edx::default();
            for (k, v) in items {
                if db.contains_key(&k) {
                    res.insert(k, v);
                } else {
                    db.insert(k, v);
                }
            }
            Ok(res)
        }

        async fn upsert(&self, old_values: Edx, new_values: Edx) -> Result<Edx, InMemoryDbError> {
            let edx = &mut self.lock().expect("couldn't lock the table");
            // Ensures an value is present inside the EDX for each given old value.
            if old_values.keys().any(|token| !edx.contains_key(token)) {
                return Err(InMemoryDbError(format!(
                    "missing EDX tokens {:?}",
                    old_values
                        .keys()
                        .filter(|token| !edx.contains_key(*token))
                        .collect::<Vec<_>>()
                )));
            }

            let mut res = HashMap::new();
            for (token, new_ciphertext) in new_values {
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

            Ok(Edx::from(res))
        }
    }

    const N_WORKERS: usize = 100;

    #[test]
    fn test_insert_then_dump_and_fetch() {
        let db = InMemoryDb::default();
        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                spawn(move || -> Result<_, <InMemoryDb as DbInterface>::Error> {
                    let mut rng = CsRng::from_entropy();
                    let mut tok = Token::default();
                    rng.fill_bytes(&mut tok);
                    let data = vec![i as u8];
                    let rejected_items =
                        block_on(db.insert(Edx::from(HashMap::from_iter([(tok, data.clone())]))))?;
                    if rejected_items.is_empty() {
                        Ok((tok, data))
                    } else {
                        Err(InMemoryDbError("some items were rejected".to_string()))
                    }
                })
            })
            .collect::<Vec<_>>();

        let inserted_dx = handles
            .into_iter()
            .flat_map(|h| h.join())
            .collect::<Result<HashMap<_, _>, _>>()
            .unwrap();

        let stored_dx = block_on(db.dump()).unwrap();
        assert_eq!(inserted_dx, *stored_dx);

        let res = block_on(db.fetch(inserted_dx.keys().copied().collect())).unwrap();
        assert_eq!(inserted_dx, *res);
    }

    #[test]
    fn test_concurrent_upsert() {
        let db = InMemoryDb::default();
        let mut rng = CsRng::from_entropy();
        let mut tok = Token::default();
        rng.fill_bytes(&mut tok);

        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                spawn(move || -> Result<_, <InMemoryDb as DbInterface>::Error> {
                    let data = vec![i as u8];
                    let mut rejected_items =
                        block_on(db.insert(Edx::from(HashMap::from_iter([(tok, data.clone())]))))?;
                    while !rejected_items.is_empty() {
                        let mut new_data = rejected_items
                            .get(&tok)
                            .ok_or_else(|| {
                                InMemoryDbError(format!(
                                    "thread {i} did not retrieve token current value"
                                ))
                            })?
                            .clone();
                        new_data.extend(&data);
                        rejected_items = block_on(db.upsert(
                            rejected_items,
                            Edx::from(HashMap::from_iter([(tok, new_data)])),
                        ))?;
                    }
                    Ok(())
                })
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let dx = block_on(db.dump()).unwrap();
        assert_eq!(dx.len(), 1);

        let stored_data = dx.get(&tok).unwrap();
        let ids = stored_data.iter().copied().collect::<HashSet<_>>();

        // Check all threads have successfully inserted their ID.
        assert_eq!(ids, (0..N_WORKERS as u8).collect::<HashSet<u8>>());
    }
}
