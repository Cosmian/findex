use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::DerefMut,
    sync::{Mutex, MutexGuard},
};

use crate::{address::Address, error::Error, Stm};
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use cosmian_crypto_core::{
    reexport::rand_core::RngCore, Aes256Gcm, CsRng, Dem, FixedSizeCBytes, Instantiable, Nonce,
    RandomFixedSizeCBytes, Secret, SymmetricKey,
};

const ADDRESS_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;

pub struct ObfuscationLayer<Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> {
    permutation_key: SymmetricKey<KEY_LENGTH>,
    encryption_key: SymmetricKey<32>,
    cache: Mutex<HashMap<(Address<ADDRESS_LENGTH>, Vec<u8>), Vec<u8>>>,
    rng: Mutex<CsRng>,
    stm: Memory,
}

impl<Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> ObfuscationLayer<Memory> {
    pub fn new(seed: Secret<KEY_LENGTH>, rng: CsRng, stm: Memory) -> Self {
        let permutation_key = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        let encryption_key = SymmetricKey::derive(&seed, &[0]).expect("secret is large enough");
        Self {
            permutation_key,
            encryption_key,
            cache: Mutex::new(HashMap::new()),
            rng: Mutex::new(rng),
            stm,
        }
    }

    pub fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned lock")
    }

    /// Shuffles the given list of values.
    fn shuffle<T>(&self, mut v: Vec<T>) -> Vec<T> {
        v.sort_by(|_, _| {
            if self.rng().next_u32() % 2 == 0 {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        });
        v
    }

    pub fn encrypt(
        &self,
        ptx: &[u8],
        tok: &Address<ADDRESS_LENGTH>,
    ) -> Result<Vec<u8>, Error<Memory::Error>> {
        let nonce = Nonce::<{ Aes256Gcm::NONCE_LENGTH }>::new(&mut *self.rng());
        let ctx = Aes256Gcm::new(&self.encryption_key)
            .encrypt(&nonce, ptx, Some(tok))
            .map_err(Error::Encryption)?;
        let ctx = [nonce.as_bytes(), &ctx].concat();
        Ok(ctx)
    }

    pub fn decrypt(
        &self,
        ctx: &[u8],
        tok: &Address<ADDRESS_LENGTH>,
    ) -> Result<Vec<u8>, Error<Memory::Error>> {
        if ctx.len() < Aes256Gcm::NONCE_LENGTH {
            return Err(Error::Parsing("ciphertext too small".to_string()));
        }
        let nonce = Nonce::try_from_slice(&ctx[..Aes256Gcm::NONCE_LENGTH])
            .map_err(|e| Error::Parsing(e.to_string()))?;
        let ptx = Aes256Gcm::new(&self.encryption_key)
            .decrypt(&nonce, &ctx[Aes256Gcm::NONCE_LENGTH..], Some(tok))
            .map_err(Error::Encryption)?;
        Ok(ptx)
    }

    pub fn permute(&self, mut a: Address<ADDRESS_LENGTH>) -> Address<ADDRESS_LENGTH> {
        let e = Aes256::new(GenericArray::from_slice(&self.permutation_key));
        e.encrypt_block(GenericArray::from_mut_slice(&mut a));
        a
    }

    pub fn bind(&self, k: (Address<ADDRESS_LENGTH>, Vec<u8>), v: Vec<u8>) {
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

impl<
        Memory: Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>, // use a `Vec<u8>` because `const` generics
                                                                        // are not allowed in `const` operations
    > Stm for ObfuscationLayer<Memory>
{
    type Address = Address<ADDRESS_LENGTH>;

    type Word = Memory::Word;

    type Error = Error<Memory::Error>;

    fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<(Self::Address, Option<Self::Word>)>, Self::Error> {
        let addresses = self.shuffle(addresses);
        let tokens = addresses.iter().cloned().map(|a| self.permute(a)).collect();
        let bindings = self.stm.batch_read(tokens)?;
        addresses
            .into_iter()
            .zip(bindings.iter())
            .map(|(a, (tok, ctx))| {
                ctx.as_deref()
                    .map(|ctx| self.decrypt(ctx, tok))
                    .transpose()
                    .map(|maybe_ctx| (a, maybe_ctx))
            })
            .collect()
    }

    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (a, v) = guard;
        let tok = self.permute(a.clone());
        let old = v.and_then(|v| self.find(&(a.clone(), v)));

        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                self.encrypt(&v, &tok).map(|ctx| (tok, ctx))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let ctx = self.stm.guarded_write((tok.clone(), old), bindings)?;

        if let Some(ctx) = ctx {
            let ptx = self.decrypt(&ctx, &tok)?;
            self.bind((a, ptx.clone()), ctx);
            Ok(Some(ptx))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};

    use crate::{
        address::Address,
        kv::KvStore,
        obf::{ObfuscationLayer, ADDRESS_LENGTH},
        stm::Stm,
    };

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::new();
        let obf = ObfuscationLayer::new(seed, rng.clone(), kv);
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = vec![1];
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
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::new();
        let obf = ObfuscationLayer::new(seed, rng.clone(), kv);

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), vec![2]),
                    (val_addr_1.clone(), vec![1]),
                    (val_addr_2.clone(), vec![1])
                ]
            )
            .unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), vec![2]),
                    (val_addr_1.clone(), vec![3]),
                    (val_addr_2.clone(), vec![3])
                ]
            )
            .unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            obf.guarded_write(
                (header_addr.clone(), Some(vec![2])),
                vec![
                    (header_addr.clone(), vec![4]),
                    (val_addr_3.clone(), vec![2]),
                    (val_addr_4.clone(), vec![2])
                ]
            )
            .unwrap(),
            Some(vec![4])
        );

        assert_eq!(
            HashSet::<(Address<ADDRESS_LENGTH>, Option<Vec<u8>>)>::from_iter([
                (header_addr.clone(), Some(vec![4])),
                (val_addr_1.clone(), Some(vec![1])),
                (val_addr_2.clone(), Some(vec![1])),
                (val_addr_3.clone(), Some(vec![2])),
                (val_addr_4.clone(), Some(vec![2]))
            ]),
            HashSet::from_iter(
                obf.batch_read(vec![
                    header_addr,
                    val_addr_1,
                    val_addr_2,
                    val_addr_3,
                    val_addr_4
                ])
                .unwrap()
            ),
        )
    }
}
