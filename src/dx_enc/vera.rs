use async_trait::async_trait;
use cosmian_crypto_core::{kdf256, Secret};

use crate::{CoreError, DbInterface, Error, MIN_SEED_LENGTH};

use super::{
    primitives::{Dem, Kmac},
    structs::{Tag, TAG_LENGTH},
    CsRhDxEnc, Dx, DynRhDxEnc, Edx, TagSet, Token,
};

pub struct Vera<DbConnection: DbInterface> {
    connection: DbConnection,
    kmac: Kmac,
    dem: Dem,
}

impl<DbConnection: DbInterface> Vera<DbConnection> {
    const TOKEN_INFO: &'static [u8] = b"Token derivation info.";

    /// Returns the token associated to the given tag.
    fn tokenize(&self, tag: &Tag) -> Token {
        self.kmac.hash(tag, Self::TOKEN_INFO)
    }

    /// Returns the EDX corresponding to the given DX.
    fn prepare<const VALUE_LENGTH: usize>(&self, dx: &Dx<VALUE_LENGTH>) -> Result<Edx, CoreError> {
        dx.iter()
            .map(|(tag, val)| {
                let tok = self.tokenize(tag);
                let ctx = self.dem.encrypt(&[tag, val.as_slice()].concat(), &tok)?;
                Ok((tok, ctx))
            })
            .collect()
    }

    /// Returns the DX corresponding to the given EDX.
    fn resolve<const VALUE_LENGTH: usize>(&self, edx: &Edx) -> Result<Dx<VALUE_LENGTH>, CoreError> {
        edx.iter()
            .map(|(tok, ctx)| {
                let ptx = self.dem.decrypt(ctx, tok)?;
                if ptx.len() != TAG_LENGTH + VALUE_LENGTH {
                    Err(CoreError::Crypto(format!(
                        "invalid length for decrypted EDX value: found {} while {} was expected",
                        ptx.len(),
                        TAG_LENGTH + VALUE_LENGTH
                    )))
                } else {
                    let tag = Tag::try_from(&ptx[..TAG_LENGTH])
                        .expect("above check ensures length is correct");
                    let val = <[u8; VALUE_LENGTH]>::try_from(&ptx[TAG_LENGTH..])
                        .expect("above check ensures length is correct");
                    Ok((tag, val))
                }
            })
            .collect()
    }
}

#[async_trait(?Send)]
impl<const VALUE_LENGTH: usize, DbConnection: DbInterface + Clone> DynRhDxEnc<VALUE_LENGTH>
    for Vera<DbConnection>
{
    type Error = Error<DbConnection::Error>;
    type DbConnection = DbConnection;

    fn setup(seed: &[u8], connection: DbConnection) -> Result<Self, Self::Error> {
        let mut vera_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut vera_seed, seed, b"VERA seed derivation");
        let dem = Dem::setup(&vera_seed)?;
        let kmac = Kmac::setup(&vera_seed)?;
        Ok(Self {
            connection,
            kmac,
            dem,
        })
    }

    fn rekey(&self, seed: &[u8]) -> Result<Self, Self::Error> {
        <Self as DynRhDxEnc<VALUE_LENGTH>>::setup(seed, self.connection.clone())
    }

    async fn get(&self, tags: TagSet) -> Result<Dx<VALUE_LENGTH>, Self::Error> {
        let tokens = tags.iter().map(|tag| self.tokenize(tag)).collect();
        let edx = self.connection.fetch(tokens).await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }

    async fn insert(&self, dx: Dx<VALUE_LENGTH>) -> Result<Dx<VALUE_LENGTH>, Self::Error> {
        let edx = self.prepare(&dx)?;
        let edx = self.connection.insert(edx).await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }

    async fn delete(&self, tags: TagSet) -> Result<(), Self::Error> {
        let tokens = tags.iter().map(|tag| self.tokenize(tag)).collect();
        self.connection
            .delete(tokens)
            .await
            .map_err(Self::Error::from)
    }
}

#[async_trait(?Send)]
impl<const VALUE_LENGTH: usize, DbConnection: DbInterface + Clone> CsRhDxEnc<VALUE_LENGTH>
    for Vera<DbConnection>
{
    async fn insert(&self, dx: Dx<VALUE_LENGTH>) -> Result<(Dx<VALUE_LENGTH>, Edx), Self::Error> {
        let edx = self.prepare(&dx)?;
        let edx = self.connection.insert(edx).await?;
        let dx = self.resolve(&edx)?;
        Ok((dx, edx))
    }

    async fn upsert(
        &self,
        old_edx: Edx,
        new_dx: Dx<VALUE_LENGTH>,
    ) -> Result<(Dx<VALUE_LENGTH>, Edx), Self::Error> {
        let new_edx = self.prepare(&new_dx)?;
        let cur_edx = self.connection.upsert(old_edx, new_edx).await?;
        let cur_dx = self.resolve(&cur_edx)?;
        Ok((cur_dx, cur_edx))
    }

    async fn rebuild(mut self, seed: &[u8]) -> Result<Self, Self::Error> {
        let old_edx = self.connection.dump().await?;
        let dx: Dx<VALUE_LENGTH> = self.resolve(&old_edx)?;

        self = <Vera<DbConnection> as DynRhDxEnc<VALUE_LENGTH>>::setup(seed, self.connection)?;

        let new_edx = self.prepare(&dx)?;
        let res = self.connection.insert(new_edx).await?;
        if res.is_empty() {
            self.connection
                .delete(old_edx.keys().cloned().collect())
                .await?;
        } else {
            let tokens = dx.keys().map(|tag| self.tokenize(tag)).collect();
            self.connection.delete(tokens).await?;
        }
        Ok(self)
    }

    async fn dump(&self) -> Result<Dx<VALUE_LENGTH>, Self::Error> {
        let edx = self.connection.dump().await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }
}
