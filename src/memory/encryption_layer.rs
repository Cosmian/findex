use std::{fmt::Debug, ops::Deref, sync::Arc};

use crate::{Address, ByteArray, KEY_LENGTH, MemoryADT, Secret, Word, symmetric_key::SymmetricKey};
use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use xts_mode::Xts128;

#[derive(Clone)]
struct ClonableXts(Arc<Xts128<Aes256>>);

impl Debug for ClonableXts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ClonableXts").finish()
    }
}

impl Deref for ClonableXts {
    type Target = Xts128<Aes256>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The encryption layers is built on top of an encrypted memory implementing the `MemoryADT` and
/// exposes a plaintext virtual memory interface implementing the `MemoryADT`.
///
/// This type is thread-safe.
#[derive(Debug, Clone)]
pub struct MemoryEncryptionLayer<const WORD_LENGTH: usize, Memory: MemoryADT<WORD_LENGTH>> {
    aes: Aes256,
    xts: ClonableXts,
    mem: Memory,
}

impl<const WORD_LENGTH: usize, Memory: MemoryADT<WORD_LENGTH>>
    MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    /// Instantiates a new memory encryption layer.
    pub fn new(seed: &Secret<KEY_LENGTH>, stm: Memory) -> Self {
        let k_p = SymmetricKey::<KEY_LENGTH>::derive(seed, &[0]).expect("secret is large enough");
        let k_e1 =
            SymmetricKey::<{ KEY_LENGTH }>::derive(seed, &[1]).expect("secret is large enough");
        let k_e2 =
            SymmetricKey::<{ KEY_LENGTH }>::derive(seed, &[2]).expect("secret is large enough");
        let aes = Aes256::new(GenericArray::from_slice(&k_p));
        let aes_e1 = Aes256::new(GenericArray::from_slice(&k_e1));
        let aes_e2 = Aes256::new(GenericArray::from_slice(&k_e2));
        // The 128 in the XTS name refer to the block size. AES-256 is used here, which confers
        // 128 bits of PQ security.
        let xts = ClonableXts(Arc::new(Xts128::new(aes_e1, aes_e2)));
        Self { aes, xts, mem: stm }
    }

    /// Permutes the given memory address.
    fn permute(&self, mut a: Address) -> Address {
        self.aes
            .encrypt_block(GenericArray::from_mut_slice(&mut *a));
        a
    }

    /// Encrypts this plaintext using its encrypted memory address as tweak.
    fn encrypt(&self, mut ptx: Word<WORD_LENGTH>, tok: Address) -> Word<WORD_LENGTH> {
        self.xts.encrypt_sector(&mut *ptx, tok.into());
        ptx
    }

    /// Decrypts this ciphertext using its encrypted memory address as tweak.
    fn decrypt(&self, mut ctx: Word<WORD_LENGTH>, tok: Address) -> Word<WORD_LENGTH> {
        self.xts.decrypt_sector(&mut *ctx, tok.into());
        ctx
    }
}

impl<const WORD_LENGTH: usize, Memory: Send + Sync + MemoryADT<WORD_LENGTH>> MemoryADT<WORD_LENGTH>
    for MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    type Error = Memory::Error;

    async fn batch_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<ByteArray<WORD_LENGTH>>>, Self::Error> {
        let tokens = addresses.into_iter().map(|a| self.permute(a)).collect();
        let bindings = self.mem.batch_read(Vec::clone(&tokens)).await?;
        Ok(bindings
            .into_iter()
            .zip(tokens)
            .map(|(ctx, tok)| ctx.map(|ctx| self.decrypt(ctx, tok)))
            .collect())
    }

    async fn guarded_write(
        &self,
        guard: (Address, Option<Word<WORD_LENGTH>>),
        bindings: Vec<(Address, Word<WORD_LENGTH>)>,
    ) -> Result<Option<Word<WORD_LENGTH>>, Self::Error> {
        let (a, v) = guard;
        let tok = self.permute(a);
        let old = v.map(|v| self.encrypt(v, tok.clone()));
        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                let ctx = self.encrypt(v, tok.clone());
                (tok, ctx)
            })
            .collect();
        let cur = self.mem.guarded_write((tok.clone(), old), bindings).await?;
        let res = cur.map(|ctx| self.decrypt(ctx, tok));
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use aes::{
        Aes256,
        cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray},
    };
    use futures::executor::block_on;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{
        Address, MemoryADT, Word,
        memory::{MemoryEncryptionLayer, in_memory_store::InMemory},
        secret::Secret,
        symmetric_key::SymmetricKey,
    };

    const WORD_LENGTH: usize = 128;

    #[test]
    fn test_address_permutation() {
        let mut rng = ChaChaRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let k_p = SymmetricKey::<32>::derive(&seed, &[0]).expect("secret is large enough");
        let aes = Aes256::new(GenericArray::from_slice(&k_p));
        let memory = InMemory::<WORD_LENGTH>::default();
        let obf = MemoryEncryptionLayer::new(&seed, memory);
        let a = Address::random(&mut rng);
        let mut tok = obf.permute(a.clone());
        assert_ne!(a, tok);
        aes.decrypt_block(GenericArray::from_mut_slice(&mut *tok));
        assert_eq!(a, tok);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = ChaChaRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let memory = InMemory::<WORD_LENGTH>::default();
        let obf = MemoryEncryptionLayer::new(&seed, memory);
        let tok = Address::random(&mut rng);
        let ptx = Word::<WORD_LENGTH>::from([1; WORD_LENGTH]);
        let ctx = obf.encrypt(ptx.clone(), tok.clone());
        let res = obf.decrypt(ctx, tok);
        assert_eq!(ptx.len(), res.len());
        assert_eq!(ptx, res);
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let mut rng = ChaChaRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let memory = InMemory::<WORD_LENGTH>::default();
        let obf = MemoryEncryptionLayer::new(&seed, memory);

        let header_addr = Address::random(&mut rng);

        let val_addr_1 = Address::random(&mut rng);
        let val_addr_2 = Address::random(&mut rng);
        let val_addr_3 = Address::random(&mut rng);
        let val_addr_4 = Address::random(&mut rng);

        assert_eq!(
            block_on(obf.guarded_write((header_addr.clone(), None), vec![
                (header_addr.clone(), [2; WORD_LENGTH].into()),
                (val_addr_1.clone(), [1; WORD_LENGTH].into()),
                (val_addr_2.clone(), [1; WORD_LENGTH].into())
            ]))
            .unwrap(),
            None
        );

        assert_eq!(
            block_on(obf.guarded_write((header_addr.clone(), None), vec![
                (header_addr.clone(), [2; WORD_LENGTH].into()),
                (val_addr_1.clone(), [3; WORD_LENGTH].into()),
                (val_addr_2.clone(), [3; WORD_LENGTH].into())
            ]))
            .unwrap(),
            Some([2; WORD_LENGTH].into())
        );

        assert_eq!(
            block_on(obf.guarded_write(
                (header_addr.clone(), Some([2; WORD_LENGTH].into())),
                vec![
                    (header_addr.clone(), [4; WORD_LENGTH].into()),
                    (val_addr_3.clone(), [2; WORD_LENGTH].into()),
                    (val_addr_4.clone(), [2; WORD_LENGTH].into())
                ]
            ))
            .unwrap(),
            Some([2; WORD_LENGTH].into())
        );

        assert_eq!(
            vec![
                Some([4; WORD_LENGTH].into()),
                Some([1; WORD_LENGTH].into()),
                Some([1; WORD_LENGTH].into()),
                Some([2; WORD_LENGTH].into()),
                Some([2; WORD_LENGTH].into())
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
