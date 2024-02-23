use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    ops::Deref,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_crypto_core::CryptoCoreError;

use super::*;
use crate::Token;

#[derive(Debug)]
pub struct InMemoryDbError(pub String);

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

impl Serializable for InMemoryDb {
    type Error = InMemoryDbError;

    fn length(&self) -> usize {
        self.lock()
            .expect("could not lock mutex")
            .deref()
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum()
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        let table = &*self.lock().expect("could not lock mutex");
        let mut n = ser.write_leb128_u64(table.len() as u64)?;
        for (k, v) in table.iter() {
            n += ser.write_array(k)?;
            n += ser.write_vec(v)?;
        }
        Ok(n)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let n = de.read_leb128_u64()? as usize;
        let mut table = HashMap::with_capacity(n);
        for _ in 0..n {
            let k = de.read_array::<{ Token::LENGTH }>()?;
            let v = de.read_vec()?;
            table.insert(k.into(), v);
        }

        Ok(Self(Arc::new(Mutex::new(Edx::from(table)))))
    }
}

impl EdxDbInterface for InMemoryDb {
    type Error = InMemoryDbError;

    async fn delete(&self, items: Set<Token>) -> Result<(), Self::Error> {
        let edx = &mut self.lock().expect("could not lock mutex");
        for token in &*items {
            edx.remove(token);
        }
        Ok(())
    }

    async fn dump(&self) -> Result<Edx, Self::Error> {
        Ok(self.lock().expect("could not lock table").clone())
    }

    async fn fetch(&self, tokens: Set<Token>) -> Result<Edx, InMemoryDbError> {
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
            if let Some(current_value) = db.get(&k) {
                res.insert(k, current_value.clone());
            } else {
                db.insert(k, v);
            }
        }
        Ok(res)
    }

    async fn upsert(&self, old_values: Edx, new_values: Edx) -> Result<Edx, InMemoryDbError> {
        let edx = &mut self.lock().expect("couldn't lock the table");
        // Ensures a value is present inside the EDX for each given old value.
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

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        thread::spawn,
    };

    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use futures::executor::block_on;

    use crate::{
        db::in_memory_db::{InMemoryDb, InMemoryDbError},
        Token,
    };

    use super::*;

    const N_WORKERS: usize = 100;

    /// Tries inserting `N_WORKERS` data using random tokens. Then verifies the
    /// inserted, dumped and fetched DX are identical.
    #[test]
    fn insert_then_dump_and_fetch() {
        let mut rng = CsRng::from_entropy();
        let db = InMemoryDb::default();
        let inserted_dx = (0..N_WORKERS)
            .map(|i| {
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
            .collect::<Result<HashMap<_, _>, _>>()
            .unwrap();

        let dumped_dx = block_on(db.dump()).unwrap();
        assert_eq!(inserted_dx, *dumped_dx);

        let fetched_dx = block_on(db.fetch(inserted_dx.keys().copied().collect())).unwrap();
        assert_eq!(inserted_dx, *fetched_dx);
    }

    /// Tries concurrently upserting `N_WORKERS` IDs on the same token. Then
    /// verifies each one have been successfully upserted.
    #[test]
    fn concurrent_upsert() {
        let db = InMemoryDb::default();
        let mut rng = CsRng::from_entropy();
        let mut tok = Token::default();
        rng.fill_bytes(&mut tok);

        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                spawn(
                    move || -> Result<_, <InMemoryDb as EdxDbInterface>::Error> {
                        let data = vec![i as u8];
                        let mut rejected_items = block_on(
                            db.insert(Edx::from(HashMap::from_iter([(tok, data.clone())]))),
                        )?;
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
                    },
                )
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let dx = block_on(db.dump()).unwrap();
        assert_eq!(dx.len(), 1);

        let stored_data = dx.get(&tok).unwrap();
        let stored_ids = stored_data.iter().copied().collect::<HashSet<_>>();
        assert_eq!(stored_ids, (0..N_WORKERS as u8).collect::<HashSet<u8>>());
    }
}
