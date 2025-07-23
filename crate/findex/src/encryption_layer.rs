use aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use cosmian_crypto_core::{Secret, SymmetricKey};
use cosmian_memories::{ADDRESS_LENGTH, Address, MemoryADT};
use std::{fmt::Debug, ops::Deref, sync::Arc};
use xts_mode::Xts128;

/// Using 32-byte cryptographic keys allows achieving post-quantum resistance
/// with the AES primitive.
pub const KEY_LENGTH: usize = 32;

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

/// The encryption layers is built on top of an encrypted memory implementing
/// the `MemoryADT` and exposes a plaintext virtual memory interface
/// implementing the `MemoryADT`.
///
/// This type is thread-safe.
#[derive(Debug, Clone)]
pub struct MemoryEncryptionLayer<
    const WORD_LENGTH: usize,
    Memory: MemoryADT<Address = Address<ADDRESS_LENGTH>>,
> {
    aes: Aes256,
    xts: ClonableXts,
    mem: Memory,
}

impl<
    const WORD_LENGTH: usize,
    Memory: Send + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> MemoryEncryptionLayer<WORD_LENGTH, Memory>
{
    /// Instantiates a new memory encryption layer.
    pub fn new(seed: &Secret<KEY_LENGTH>, stm: Memory) -> Self {
        let k_p = SymmetricKey::<KEY_LENGTH>::derive(seed, &[0]).expect("secret is large enough");
        let k_e1 =
            SymmetricKey::<{ KEY_LENGTH }>::derive(seed, &[1]).expect("secret is large enough");
        let k_e2 =
            SymmetricKey::<{ KEY_LENGTH }>::derive(seed, &[2]).expect("secret is large enough");
        let aes = Aes256::new(GenericArray::from_slice(&*k_p));
        let aes_e1 = Aes256::new(GenericArray::from_slice(&*k_e1));
        let aes_e2 = Aes256::new(GenericArray::from_slice(&*k_e2));
        // The 128 in the XTS name refer to the block size. AES-256 is used
        // here, which confers 128 bits of PQ security.
        let xts = ClonableXts(Arc::new(Xts128::new(aes_e1, aes_e2)));
        Self { aes, xts, mem: stm }
    }

    /// Permutes the given memory address.
    fn permute(&self, mut a: Memory::Address) -> Memory::Address {
        self.aes
            .encrypt_block(GenericArray::from_mut_slice(&mut *a));
        a
    }

    /// Encrypts this plaintext using its encrypted memory address as tweak.
    fn encrypt(&self, mut ptx: [u8; WORD_LENGTH], tok: [u8; ADDRESS_LENGTH]) -> [u8; WORD_LENGTH] {
        self.xts.encrypt_sector(&mut ptx, tok);
        ptx
    }

    /// Decrypts this ciphertext using its encrypted memory address as tweak.
    fn decrypt(&self, mut ctx: [u8; WORD_LENGTH], tok: [u8; ADDRESS_LENGTH]) -> [u8; WORD_LENGTH] {
        self.xts.decrypt_sector(&mut ctx, tok);
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

    type Error = Memory::Error;

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
        let (address, v) = guard;
        let tok = self.permute(address);
        let old = v.map(|v| self.encrypt(v, *tok));
        let bindings = bindings
            .into_iter()
            .map(|(a, v)| {
                let tok = self.permute(a);
                let ctx = self.encrypt(v, *tok);
                (tok, ctx)
            })
            .collect();
        let cur = self.mem.guarded_write((tok, old), bindings).await?;
        let res = cur.map(|ctx| self.decrypt(ctx, *tok));
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::MemoryEncryptionLayer;
    use cosmian_crypto_core::{
        CsRng, Sampling, Secret,
        reexport::rand_core::{CryptoRngCore, SeedableRng},
    };
    use cosmian_memories::{
        ADDRESS_LENGTH, Address, InMemory,
        test_utils::{
            gen_seed, test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
        },
    };

    const WORD_LENGTH: usize = 128;

    fn create_memory<const WORD_LENGTH: usize>(
        rng: &mut impl CryptoRngCore,
    ) -> MemoryEncryptionLayer<WORD_LENGTH, InMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>>
    {
        let seed = Secret::random(rng);
        let memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        MemoryEncryptionLayer::new(&seed, memory)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = CsRng::from_entropy();
        let obf = create_memory(&mut rng);
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = [1; WORD_LENGTH];
        let ctx = obf.encrypt(ptx, *tok);
        let res = obf.decrypt(ctx, *tok);
        assert_eq!(ptx.len(), res.len());
        assert_eq!(ptx, res);
    }

    #[tokio::test]
    async fn test_sequential_read_write() {
        let mem = create_memory(&mut CsRng::from_entropy());
        test_single_write_and_read::<WORD_LENGTH, _>(&mem, gen_seed()).await;
    }

    #[tokio::test]
    async fn test_sequential_wrong_guard() {
        let mem = create_memory(&mut CsRng::from_entropy());
        test_wrong_guard::<WORD_LENGTH, _>(&mem, gen_seed()).await;
    }

    #[tokio::test]
    async fn test_concurrent_read_write() {
        let mem = create_memory(&mut CsRng::from_entropy());
        test_guarded_write_concurrent::<16, _, agnostic_lite::tokio::TokioSpawner>(
            &mem,
            gen_seed(),
            None,
        )
        .await;
    }
}
