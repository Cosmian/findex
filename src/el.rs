use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{address::Address, error::Error, MemoryADT, ADDRESS_LENGTH, KEY_LENGTH};
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use cosmian_crypto_core::{
    Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, Secret,
    SymmetricKey,
};

/// The encryption layers is built on top of an encrypted memory implementing the `MemoryADT` and
/// exposes a plaintext virtual memory interface implementing the `MemoryADT`.
///
/// This type is thread-safe.
#[derive(Debug, Clone)]
pub struct MemoryEncryptionLayer<
    const WORD_LENGTH: usize,
    Memory: MemoryADT<Address = Address<ADDRESS_LENGTH>>,
> {
    k_p: SymmetricKey<KEY_LENGTH>,
    k_e: SymmetricKey<KEY_LENGTH>,
    cch: Arc<Mutex<HashMap<Address<ADDRESS_LENGTH>, HashMap<[u8; WORD_LENGTH], Memory::Word>>>>,
    rng: Arc<Mutex<CsRng>>,
    mem: Memory,
}

impl<
        const WORD_LENGTH: usize,
        Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    /// Instantiates a new memory encryption layer.
    pub fn new(seed: Secret<KEY_LENGTH>, rng: Arc<Mutex<CsRng>>, stm: Memory) -> Self {
        let k_p = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        let k_e = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        let cch = Arc::new(Mutex::new(HashMap::new()));
        Self {
            k_p,
            k_e,
            cch,
            rng,
            mem: stm,
        }
    }

    #[inline(always)]
    fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned lock")
    }

    /// Retains values cached for the given keys only.
    pub fn retain_cached_keys(&self, keys: &HashSet<Memory::Address>) {
        self.cch
            .lock()
            .expect("poisoned mutex")
            .deref_mut()
            .retain(|k, _| keys.contains(k));
    }

    /// Decrypts the given value and caches the ciphertext.
    fn find_or_encrypt(
        &self,
        ptx: &[u8; WORD_LENGTH],
        tok: &Memory::Address,
    ) -> Result<Vec<u8>, Error<Memory::Address, Memory::Error>> {
        let mut cache = self.cch.lock().expect("poisoned lock");
        if let Some(bindings) = cache.get_mut(tok) {
            let ctx = bindings.get(ptx).cloned();
            if let Some(ctx) = ctx {
                Ok(ctx)
            } else {
                let ctx = self.encrypt(ptx, tok)?;
                bindings.insert(*ptx, ctx.clone());
                Ok(ctx)
            }
        } else {
            // token is not marked
            drop(cache);
            self.encrypt(ptx, tok)
        }
    }

    /// Decrypts the given value and caches the ciphertext.
    fn decrypt_and_bind(
        &self,
        ctx: Vec<u8>,
        tok: &Memory::Address,
    ) -> Result<[u8; WORD_LENGTH], Error<Memory::Address, Memory::Error>> {
        let ptx = self.decrypt(&ctx, tok)?;
        self.bind(tok, ptx, ctx);
        Ok(ptx)
    }

    /// Encrypts this plaintext under this associated data
    fn encrypt(
        &self,
        ptx: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>, Error<Memory::Address, Memory::Error>> {
        let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *self.rng());
        let ctx = Aes256Gcm::new(&self.k_e)
            .encrypt(&nonce, ptx, Some(ad))
            .map_err(Error::Crypto)?;
        Ok([nonce.as_bytes(), &ctx].concat())
    }

    /// Decrypts this ciphertext under this associated data.
    fn decrypt(
        &self,
        ctx: &[u8],
        ad: &[u8],
    ) -> Result<[u8; WORD_LENGTH], Error<Memory::Address, Memory::Error>> {
        if ctx.len() < Aes256Gcm::NONCE_LENGTH {
            return Err(Error::Parsing("ciphertext too small".to_string()));
        }
        let nonce = Nonce::try_from_slice(&ctx[..Aes256Gcm::NONCE_LENGTH])
            .map_err(|e| Error::Parsing(e.to_string()))?;
        let ptx = Aes256Gcm::new(&self.k_e)
            .decrypt(&nonce, &ctx[Aes256Gcm::NONCE_LENGTH..], Some(ad))
            .map_err(Error::Crypto)?;
        <[u8; WORD_LENGTH]>::try_from(ptx.as_slice()).map_err(|e| Error::Conversion(e.to_string()))
    }

    /// Permutes the given memory address.
    fn permute(&self, mut a: Memory::Address) -> Memory::Address {
        Aes256::new(GenericArray::from_slice(&self.k_p))
            .encrypt_block(GenericArray::from_mut_slice(&mut a));
        a
    }

    /// Binds the given (tok, ptx, ctx) triple iff this token is marked.
    fn bind(&self, tok: &Memory::Address, ptx: [u8; WORD_LENGTH], ctx: Memory::Word) {
        let mut cache = self.cch.lock().expect("poisoned lock");
        if let Some(bindings) = cache.get_mut(tok) {
            bindings.insert(ptx, ctx);
        }
    }

    /// Retrieves the ciphertext bound to the given (tok, ptx) couple.
    /// Marks the token for later binding if it does not belong to any binding.
    fn find_or_mark(
        &self,
        tok: &Memory::Address,
        ptx: &Option<[u8; WORD_LENGTH]>,
    ) -> Result<Option<Memory::Word>, <Self as MemoryADT>::Error> {
        let mut cache = self.cch.lock().expect("poisoned lock");
        if let Some(ptx) = ptx {
            if let Some(bindings) = cache.get(tok) {
                // This token is marked.
                if let Some(ctx) = bindings.get(ptx) {
                    return Ok(Some(ctx.clone()));
                }
                return Err(Error::CorruptedMemoryCache);
            }
        }
        // marking a token consists in binding it to an empty map that can later be used to
        // store ctx/ptx bindings.
        cache.entry(tok.clone()).or_default();
        Ok(None)
    }
}

impl<
        const WORD_LENGTH: usize,
        // NOTE: base-memory-word length cannot be typed since "generic parameters may not be
        // used in const operations". What we would have wanted is this:
        // ```
        // Memory: MemoryADT<
        //     Address = Address<ADDRESS_LENGTH>,
        //     Word = [u8; WORD_LENGTH + Aes256Gcm::MAC_LENGTH + Aes256Gcm::NONCE_LENGTH],
        // >,
        // ```
        Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > MemoryADT for MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    type Address = Address<ADDRESS_LENGTH>;

    type Word = [u8; WORD_LENGTH];

    type Error = Error<Self::Address, Memory::Error>;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let tokens = addresses.into_iter().map(|a| self.permute(a)).collect();
        let bindings = self.mem.batch_read(Vec::clone(&tokens)).await?;
        bindings
            .into_iter()
            .zip(tokens)
            .map(|(ctx, tok)| ctx.map(|ctx| self.decrypt_and_bind(ctx, &tok)).transpose())
            .collect()
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (a, v) = guard;
        let tok = self.permute(a);
        let old = self.find_or_mark(&tok, &v)?;
        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                self.find_or_encrypt(&v, &tok).map(|ctx| (tok, ctx))
            })
            .collect::<Result<_, _>>()?;
        let cur = self
            .mem
            .guarded_write((tok.clone(), old.clone()), bindings)
            .await?;
        let res = cur
            .clone()
            .map(|ctx| self.decrypt_and_bind(ctx, &tok))
            .transpose()?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};
    use futures::executor::block_on;

    use crate::{
        address::Address,
        el::{MemoryEncryptionLayer, ADDRESS_LENGTH},
        kv::KvStore,
        MemoryADT,
    };

    const WORD_LENGTH: usize = 1;

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf = MemoryEncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = [1; WORD_LENGTH];
        let ctx = obf.encrypt(&ptx, &tok).unwrap();
        let res = obf.decrypt(&ctx, &tok).unwrap();
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
                    (header_addr.clone(), [2]),
                    (val_addr_1.clone(), [1]),
                    (val_addr_2.clone(), [1])
                ]
            ))
            .unwrap(),
            None
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), [2]),
                    (val_addr_1.clone(), [3]),
                    (val_addr_2.clone(), [3])
                ]
            ))
            .unwrap(),
            Some([2])
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), Some([2])),
                vec![
                    (header_addr.clone(), [4]),
                    (val_addr_3.clone(), [2]),
                    (val_addr_4.clone(), [2])
                ]
            ))
            .unwrap(),
            Some([2])
        );

        assert_eq!(
            vec![Some([4]), Some([1]), Some([1]), Some([2]), Some([2])],
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
