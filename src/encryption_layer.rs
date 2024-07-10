use crate::{address::Address, error::Error, MemoryADT, ADDRESS_LENGTH, KEY_LENGTH};
use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use cosmian_crypto_core::{Secret, SymmetricKey};
use xts_mode::Xts128;

/// The encryption layers is built on top of an encrypted memory implementing the `MemoryADT` and
/// exposes a plaintext virtual memory interface implementing the `MemoryADT`.
///
/// This type is thread-safe.
#[derive(Debug, Clone)]
pub struct MemoryEncryptionLayer<
    const WORD_LENGTH: usize,
    Memory: MemoryADT<Address = Address<ADDRESS_LENGTH>>,
> {
    aes: Aes256,
    k_e: SymmetricKey<KEY_LENGTH>, // `Xts128` does not implement Clone
    mem: Memory,
}

impl<
        const WORD_LENGTH: usize,
        Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    > MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    /// Instantiates a new memory encryption layer.
    pub fn new(seed: Secret<KEY_LENGTH>, stm: Memory) -> Self {
        let k_p = SymmetricKey::<32>::derive(&seed, &[0]).expect("secret is large enough");
        let k_e = SymmetricKey::<KEY_LENGTH>::derive(&seed, &[0]).expect("secret is large enough");
        let aes = Aes256::new(GenericArray::from_slice(&k_p));
        Self { aes, k_e, mem: stm }
    }

    /// Permutes the given memory address.
    fn permute(&self, mut a: Memory::Address) -> Memory::Address {
        self.aes
            .encrypt_block(GenericArray::from_mut_slice(&mut *a));
        a
    }

    /// Encrypts this plaintext using its encrypted memory address as tweak.
    fn encrypt(&self, mut ptx: [u8; WORD_LENGTH], tok: [u8; ADDRESS_LENGTH]) -> [u8; WORD_LENGTH] {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&self.k_e[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&self.k_e[32..]));
        Xts128::new(cipher_1, cipher_2).encrypt_sector(&mut ptx, tok);
        ptx
    }

    /// Decrypts this ciphertext using its encrypted memory address as tweak.
    fn decrypt(&self, mut ctx: [u8; WORD_LENGTH], tok: [u8; ADDRESS_LENGTH]) -> [u8; WORD_LENGTH] {
        let cipher_1 = Aes256::new(GenericArray::from_slice(&self.k_e[..32]));
        let cipher_2 = Aes256::new(GenericArray::from_slice(&self.k_e[32..]));
        Xts128::new(cipher_1, cipher_2).decrypt_sector(&mut ctx, tok);
        ctx
    }
}

impl<
        const WORD_LENGTH: usize,
        Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
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
        Ok(bindings
            .into_iter()
            .zip(tokens)
            .map(|(ctx, tok)| ctx.map(|ctx| self.decrypt(ctx, *tok)))
            .collect())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (a, v) = guard;
        let tok = self.permute(a);
        let old = v.map(|v| self.encrypt(v, *tok));
        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                let ctx = self.encrypt(v, *tok);
                (tok, ctx)
            })
            .collect();
        let cur = self.mem.guarded_write((tok.clone(), old), bindings).await?;
        let res = cur.map(|ctx| self.decrypt(ctx, *tok));
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use aes::{
        cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
        Aes256,
    };
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret, SymmetricKey};
    use futures::executor::block_on;

    use crate::{
        address::Address,
        encryption_layer::{MemoryEncryptionLayer, ADDRESS_LENGTH},
        kv::KvStore,
        MemoryADT,
    };

    const WORD_LENGTH: usize = 128;

    #[test]
    fn test_address_permutation() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let k_p = SymmetricKey::<32>::derive(&seed, &[0]).expect("secret is large enough");
        let aes = Aes256::new(GenericArray::from_slice(&k_p));
        let kv = KvStore::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        let obf = MemoryEncryptionLayer::new(seed, kv);
        let a = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let mut tok = obf.permute(a.clone());
        assert_ne!(a, tok);
        aes.decrypt_block(GenericArray::from_mut_slice(&mut *tok));
        assert_eq!(a, tok);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        let obf = MemoryEncryptionLayer::new(seed, kv);
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = [1; WORD_LENGTH];
        let ctx = obf.encrypt(ptx, *tok);
        let res = obf.decrypt(ctx, *tok);
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
        let kv = KvStore::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        let obf = MemoryEncryptionLayer::new(seed, kv);

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), [2; WORD_LENGTH]),
                    (val_addr_1.clone(), [1; WORD_LENGTH]),
                    (val_addr_2.clone(), [1; WORD_LENGTH])
                ]
            ))
            .unwrap(),
            None
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), None),
                vec![
                    (header_addr.clone(), [2; WORD_LENGTH]),
                    (val_addr_1.clone(), [3; WORD_LENGTH]),
                    (val_addr_2.clone(), [3; WORD_LENGTH])
                ]
            ))
            .unwrap(),
            Some([2; WORD_LENGTH])
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), Some([2; WORD_LENGTH])),
                vec![
                    (header_addr.clone(), [4; WORD_LENGTH]),
                    (val_addr_3.clone(), [2; WORD_LENGTH]),
                    (val_addr_4.clone(), [2; WORD_LENGTH])
                ]
            ))
            .unwrap(),
            Some([2; WORD_LENGTH])
        );

        assert_eq!(
            vec![
                Some([4; WORD_LENGTH]),
                Some([1; WORD_LENGTH]),
                Some([1; WORD_LENGTH]),
                Some([2; WORD_LENGTH]),
                Some([2; WORD_LENGTH])
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
