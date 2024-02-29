use std::sync::Mutex;

use cosmian_crypto_core::{
    kdf256, reexport::rand_core::SeedableRng, Aes256Gcm, CsRng, Dem as DemTrait, Instantiable,
    Nonce, RandomFixedSizeCBytes, SymmetricKey,
};

use crate::{CoreError, MIN_SEED_LENGTH};

pub struct Kmac(SymmetricKey<{ Self::KEY_LENGTH }>);

impl Kmac {
    const KEY_LENGTH: usize = 32;

    pub fn setup(seed: &[u8]) -> Result<Self, CoreError> {
        if seed.len() < MIN_SEED_LENGTH {
            return Err(CoreError::Crypto(format!(
                "insufficient KMAC seed length: {} given, should be at least {MIN_SEED_LENGTH}-byte long",
                seed.len()
            )));
        }
        let mut key = SymmetricKey::<{ Self::KEY_LENGTH }>::default();
        kdf256!(&mut key, seed, b"KMAC key derivation");
        Ok(Self(key))
    }

    pub fn hash<const OUTPUT_LENGTH: usize>(
        &self,
        bytes: &[u8],
        info: &[u8],
    ) -> [u8; OUTPUT_LENGTH] {
        kmac!(OUTPUT_LENGTH, &*self.0, bytes, info)
    }
}

pub struct Dem {
    aead: Aes256Gcm,
    rng: Mutex<CsRng>,
}

impl Dem {
    const KEY_LENGTH: usize = 32;

    pub fn setup(seed: &[u8]) -> Result<Self, CoreError> {
        if seed.len() < MIN_SEED_LENGTH {
            return Err(CoreError::Crypto(format!(
                "insufficient DEM seed length: {} given, should be at least {MIN_SEED_LENGTH}-byte long",
                seed.len()
            )));
        }
        let mut key = SymmetricKey::<{ Self::KEY_LENGTH }>::default();
        kdf256!(&mut key, seed, b"DEM key derivation");
        let rng = CsRng::from_entropy();
        Ok(Self {
            aead: Aes256Gcm::new(&key),
            rng: Mutex::new(rng),
        })
    }

    pub fn encrypt(&self, ptx: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
        let nonce = Nonce::new(&mut *self.rng.lock().expect("poisoned lock"));
        let ctx = self
            .aead
            .encrypt(&nonce, ptx, Some(aad))
            .map_err(CoreError::from)?;
        Ok([nonce.as_bytes(), &ctx].concat())
    }

    pub fn decrypt(&self, ctx: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
        if ctx.len() < Aes256Gcm::NONCE_LENGTH {
            return Err(CoreError::Crypto(format!(
                "wrong ciphertext length: should be at least {}-byte long, but {} were given",
                Aes256Gcm::NONCE_LENGTH,
                ctx.len()
            )));
        }
        let nonce = Nonce::try_from(&ctx[..Aes256Gcm::NONCE_LENGTH])?;
        self.aead
            .decrypt(&nonce, &ctx[Aes256Gcm::NONCE_LENGTH..], Some(aad))
            .map_err(CoreError::from)
    }
}
