use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{address::Address, error::Error, Stm, ADDRESS_LENGTH, KEY_LENGTH};
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use cosmian_crypto_core::{
    Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, Secret,
    SymmetricKey,
};

#[derive(Debug)]
pub struct MemoryEncryptionLayer<Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> {
    permutation_key: SymmetricKey<KEY_LENGTH>,
    encryption_key: SymmetricKey<32>,
    cache: Arc<Mutex<HashMap<(Address<ADDRESS_LENGTH>, Vec<u8>), Vec<u8>>>>,
    rng: Arc<Mutex<CsRng>>,
    stm: Memory,
}

// NOTE: cannot enforce word length at compile time without hard-coding numbers since constant
// generics are not yet allowed in constant operations.
impl<Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> MemoryEncryptionLayer<Memory> {
    /// Instantiates a new memory encryption layer.
    pub fn new(seed: Secret<KEY_LENGTH>, rng: Arc<Mutex<CsRng>>, stm: Memory) -> Self {
        let permutation_key = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        let encryption_key = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        Self {
            permutation_key,
            encryption_key,
            cache: Arc::new(Mutex::new(HashMap::new())),
            rng,
            stm,
        }
    }

    #[inline(always)]
    fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned lock")
    }

    /// Retains values cached for the given keys only.
    pub fn retain_cached_keys(&self, keys: &HashSet<(Memory::Address, Vec<u8>)>) {
        self.cache
            .lock()
            .expect("poisoned mutex")
            .deref_mut()
            .retain(|k, _| keys.contains(k));
    }

    /// Gets the encrypted value from the cache and computes it upon cache miss.
    pub fn encrypt(
        &self,
        ptx: &[u8],
        tok: &Memory::Address,
    ) -> Result<Vec<u8>, Error<Memory::Address, Memory::Error>> {
        let k = (tok.clone(), ptx.to_vec());
        if let Some(ctx) = self.find(&k) {
            Ok(ctx)
        } else {
            let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *self.rng());
            let ctx = Aes256Gcm::new(&self.encryption_key)
                .encrypt(&nonce, ptx, Some(tok))
                .map_err(Error::Encryption)?;
            let ctx = [nonce.as_bytes(), &ctx].concat();
            self.bind(k, ctx.clone());
            Ok(ctx)
        }
    }

    /// Decrypts the given value and caches the ciphertext.
    pub fn decrypt(
        &self,
        ctx: Vec<u8>,
        tok: Memory::Address,
    ) -> Result<Vec<u8>, Error<Memory::Address, Memory::Error>> {
        if ctx.len() < Aes256Gcm::NONCE_LENGTH {
            return Err(Error::Parsing("ciphertext too small".to_string()));
        }
        let nonce = Nonce::try_from_slice(&ctx[..Aes256Gcm::NONCE_LENGTH])
            .map_err(|e| Error::Parsing(e.to_string()))?;
        let ptx = Aes256Gcm::new(&self.encryption_key)
            .decrypt(&nonce, &ctx[Aes256Gcm::NONCE_LENGTH..], Some(&tok))
            .map_err(Error::Encryption)?;
        self.bind((tok, ptx.clone()), ctx);
        Ok(ptx)
    }

    pub fn reorder(&self, mut a: Memory::Address) -> Memory::Address {
        Aes256::new(GenericArray::from_slice(&self.permutation_key))
            .decrypt_block(GenericArray::from_mut_slice(&mut a));
        a
    }

    pub fn permute(&self, mut a: Memory::Address) -> Memory::Address {
        Aes256::new(GenericArray::from_slice(&self.permutation_key))
            .encrypt_block(GenericArray::from_mut_slice(&mut a));
        a
    }

    pub fn bind(&self, k: (Memory::Address, Vec<u8>), v: Vec<u8>) {
        self.cache
            .lock()
            .expect("poisoned lock")
            .deref_mut()
            .insert(k, v);
    }

    pub fn find(&self, k: &(Address<ADDRESS_LENGTH>, Vec<u8>)) -> Option<Vec<u8>> {
        self.cache
            .lock()
            .expect("poisoned lock")
            .deref_mut()
            .get(k)
            .cloned()
    }
}

impl<Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> Stm
    for MemoryEncryptionLayer<Memory>
{
    type Address = Address<ADDRESS_LENGTH>;

    type Word = Memory::Word;

    type Error = Error<Self::Address, Memory::Error>;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let tokens: Vec<_> = addresses.into_iter().map(|a| self.permute(a)).collect();
        let bindings = self.stm.batch_read(tokens.clone()).await?;
        bindings
            .into_iter()
            .zip(tokens)
            .map(|(ctx, tok)| ctx.map(|ctx| self.decrypt(ctx, tok.clone())).transpose())
            .collect()
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (a, v) = guard;
        let tok = self.permute(a);
        let old = v.and_then(|v| self.find(&(tok.clone(), v)));

        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                self.encrypt(&v, &tok).map(|ctx| (tok, ctx))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let ctx = self.stm.guarded_write((tok.clone(), old), bindings).await?;

        if let Some(ctx) = ctx {
            let ptx = self.decrypt(ctx.clone(), tok)?;
            Ok(Some(ptx))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};
    use futures::executor::block_on;

    use crate::{
        address::Address,
        kv::KvStore,
        obf::{MemoryEncryptionLayer, ADDRESS_LENGTH},
        stm::Stm,
    };

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf = MemoryEncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = vec![1];
        let ctx = obf.encrypt(&ptx, &tok).unwrap();
        let res = obf.decrypt(ctx, tok).unwrap();
        assert_eq!(ptx.len(), res.len());
        assert_eq!(ptx, res);
    }

    /// Ensures a transaction can express an vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf = MemoryEncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), vec![2]),
                    (val_addr_1.clone(), vec![1]),
                    (val_addr_2.clone(), vec![1])
                ]
            ))
            .unwrap(),
            None
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), vec![2]),
                    (val_addr_1.clone(), vec![3]),
                    (val_addr_2.clone(), vec![3])
                ]
            ))
            .unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), Some(vec![2])),
                vec![
                    (header_addr.clone(), vec![4]),
                    (val_addr_3.clone(), vec![2]),
                    (val_addr_4.clone(), vec![2])
                ]
            ))
            .unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            vec![
                Some(vec![4]),
                Some(vec![1]),
                Some(vec![1]),
                Some(vec![2]),
                Some(vec![2])
            ],
            block_on(obf.batch_read(vec![
                header_addr,
                val_addr_1,
                val_addr_2,
                val_addr_3,
                val_addr_4
            ]))
            .unwrap()
        )
    }
}
