use std::marker::PhantomData;

use async_trait::async_trait;
use cosmian_crypto_core::{kdf256, Secret};

use crate::{CoreError, DbInterface, Error, MIN_SEED_LENGTH};

use super::{
    primitives::{Dem, Kmac},
    CsRhDxEnc, Dx, DynRhDxEnc, Edx, TagSet, Token,
};

/// Byte length of Vera's tags.
pub const TAG_LENGTH: usize = 16;

/// Vera is a CS-RH-DX-Enc scheme: it interacts with a DB to securely store a
/// dictionary (DX).
///
/// It transforms [`TAG_LENGTH`](TAG_LENGTH)-byte long tags into
/// cryptographically secure [`Token`s](Token), and stores tags alongside the
/// values in the EDX ciphertexts.
pub struct Vera<
    const VALUE_LENGTH: usize,
    DbConnection: DbInterface,
    Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
> {
    connection: DbConnection,
    kmac: Kmac,
    dem: Dem,
    item: PhantomData<Item>,
}

impl<
        const VALUE_LENGTH: usize,
        DbConnection: Clone + DbInterface,
        Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
    > Vera<VALUE_LENGTH, DbConnection, Item>
{
    const TOKEN_INFO: &'static [u8] = b"Token derivation info.";

    /// Returns the token associated to the given tag.
    fn tokenize(&self, tag: &<Self as DynRhDxEnc<VALUE_LENGTH>>::Tag) -> Token {
        self.kmac.hash(tag, Self::TOKEN_INFO)
    }

    /// Returns the EDX corresponding to the given DX.
    fn prepare(
        &self,
        dx: Dx<
            VALUE_LENGTH,
            <Self as DynRhDxEnc<VALUE_LENGTH>>::Tag,
            <Self as DynRhDxEnc<VALUE_LENGTH>>::Item,
        >,
    ) -> Result<Edx, CoreError> {
        dx.into_iter()
            .map(|(tag, val)| {
                let tok = self.tokenize(&tag);
                // TODO: zeroize DX here.
                let ctx = self
                    .dem
                    .encrypt(&[&tag.as_slice(), val.into().as_slice()].concat(), &tok)?;
                Ok((tok, ctx))
            })
            .collect()
    }

    /// Returns the DX corresponding to the given EDX.
    fn resolve(
        &self,
        edx: &Edx,
    ) -> Result<
        Dx<
            VALUE_LENGTH,
            <Self as DynRhDxEnc<VALUE_LENGTH>>::Tag,
            <Self as DynRhDxEnc<VALUE_LENGTH>>::Item,
        >,
        CoreError,
    > {
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
                    let tag = <Self as DynRhDxEnc<VALUE_LENGTH>>::Tag::try_from(&ptx[..TAG_LENGTH])
                        .expect("above check ensures length is correct");
                    let val = <[u8; VALUE_LENGTH]>::try_from(&ptx[TAG_LENGTH..])
                        .expect("above check ensures length is correct");
                    Ok((tag, val.into()))
                }
            })
            .collect()
    }
}

#[async_trait(?Send)]
impl<
        const VALUE_LENGTH: usize,
        DbConnection: DbInterface + Clone,
        Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
    > DynRhDxEnc<VALUE_LENGTH> for Vera<VALUE_LENGTH, DbConnection, Item>
{
    type Error = Error<DbConnection::Error>;
    type DbConnection = DbConnection;
    type Tag = [u8; TAG_LENGTH];
    type Item = Item;

    fn setup(seed: &[u8], connection: DbConnection) -> Result<Self, Self::Error> {
        let mut vera_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut vera_seed, seed, b"VERA seed derivation");
        let dem = Dem::setup(&vera_seed)?;
        let kmac = Kmac::setup(&vera_seed)?;
        Ok(Self {
            connection,
            kmac,
            dem,
            item: PhantomData::default(),
        })
    }

    fn rekey(&self, seed: &[u8]) -> Result<Self, Self::Error> {
        Self::setup(seed, self.connection.clone())
    }

    async fn get(
        &self,
        tags: TagSet<Self::Tag>,
    ) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error> {
        let tokens = tags.iter().map(|tag| self.tokenize(tag)).collect();
        let edx = self.connection.fetch(tokens).await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }

    async fn insert(
        &self,
        dx: Dx<VALUE_LENGTH, Self::Tag, Self::Item>,
    ) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error> {
        let edx = self.prepare(dx)?;
        let edx = self.connection.insert(edx).await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }

    async fn delete(&self, tags: TagSet<Self::Tag>) -> Result<(), Self::Error> {
        let tokens = tags.iter().map(|tag| self.tokenize(tag)).collect();
        self.connection
            .delete(tokens)
            .await
            .map_err(Self::Error::from)
    }
}

#[async_trait(?Send)]
impl<
        const VALUE_LENGTH: usize,
        DbConnection: DbInterface + Clone,
        Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
    > CsRhDxEnc<TAG_LENGTH, VALUE_LENGTH, [u8; TAG_LENGTH]>
    for Vera<VALUE_LENGTH, DbConnection, Item>
{
    async fn insert(
        &self,
        dx: Dx<VALUE_LENGTH, Self::Tag, Self::Item>,
    ) -> Result<(Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Edx), Self::Error> {
        let edx = self.prepare(dx)?;
        let edx = self.connection.insert(edx).await?;
        let dx = self.resolve(&edx)?;
        Ok((dx, edx))
    }

    async fn upsert(
        &self,
        old_edx: Edx,
        new_dx: Dx<VALUE_LENGTH, Self::Tag, Self::Item>,
    ) -> Result<(Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Edx), Self::Error> {
        let new_edx = self.prepare(new_dx)?;
        let cur_edx = self.connection.upsert(old_edx, new_edx).await?;
        let cur_dx = self.resolve(&cur_edx)?;
        Ok((cur_dx, cur_edx))
    }

    async fn rebuild(mut self, _seed: &[u8]) -> Result<Self, Self::Error> {
        todo!()
        // let old_edx = self.connection.dump().await?;
        // let dx = self.resolve(&old_edx)?;

        // self = <Vera<VALUE_LENGTH, DbConnection, Item> as DynRhDxEnc<VALUE_LENGTH>>::setup(
        //     seed,
        //     self.connection,
        // )?;

        // let new_edx = self.prepare(dx)?;
        // let res = self.connection.insert(new_edx).await?;
        // if res.is_empty() {
        //     self.connection
        //         .delete(old_edx.keys().cloned().collect())
        //         .await?;
        // } else {
        //     let tokens = dx.keys().map(|tag| self.tokenize(tag)).collect();
        //     self.connection.delete(tokens).await?;
        // }
        // Ok(self)
    }

    async fn dump(&self) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error> {
        let edx = self.connection.dump().await?;
        self.resolve(&edx).map_err(Self::Error::from)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        thread::spawn,
    };

    use cosmian_crypto_core::CsRng;
    use futures::executor::block_on;
    use rand::{RngCore, SeedableRng};

    use crate::{InMemoryDb, InMemoryDbError};

    use super::*;

    const N_WORKERS: usize = 100;
    const VALUE_LENGTH: usize = 1;
    type Item = [u8; VALUE_LENGTH];

    /// Tries inserting `N_WORKERS` data using random tokens. Then verifies the
    /// inserted, dumped and fetched DX are identical.
    #[test]
    fn test_insert_then_dump_and_fetch() {
        let mut rng = CsRng::from_entropy();
        let db = InMemoryDb::default();
        let seed = Secret::<32>::random(&mut rng);
        let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();
        let inserted_dx = (0..N_WORKERS)
            .map(|i| {
                let mut tag = [0; TAG_LENGTH];
                rng.fill_bytes(&mut tag);
                let data = [i as u8];
                let rejected_items =
                    block_on(<Vera<VALUE_LENGTH, InMemoryDb, Item> as DynRhDxEnc<
                        VALUE_LENGTH,
                    >>::insert(
                        &vera,
                        Dx::from(HashMap::from_iter([(tag, data.clone())])),
                    ))?;
                if rejected_items.is_empty() {
                    Ok((tag, data))
                } else {
                    Err(Error::<InMemoryDbError>::Crypto(
                        "some items were rejected".to_string(),
                    ))
                }
            })
            .collect::<Result<HashMap<_, _>, _>>()
            .unwrap();

        let dumped_dx = block_on(vera.dump()).unwrap();
        assert_eq!(inserted_dx, *dumped_dx);

        let fetched_dx = block_on(vera.get(inserted_dx.keys().copied().collect())).unwrap();
        assert_eq!(inserted_dx, *fetched_dx);
    }

    fn concurrent_worker_upserter(
        vera: &Vera<VALUE_LENGTH, InMemoryDb, Item>,
        tags: &[[u8; TAG_LENGTH]],
        id: u8,
    ) -> Result<(), Error<InMemoryDbError>> {
        if tags.is_empty() {
            return Err(Error::Crypto(format!("could not insert ID {id}")));
        }
        let mut moved_id = None;
        let dx_new = Dx::from(HashMap::from_iter([(tags[0], [id])]));

        // First tries to insert the worker ID for the first tag.
        let (mut dx_cur, mut edx_cur) =
            block_on(<Vera<VALUE_LENGTH, InMemoryDb, Item> as CsRhDxEnc<
                TAG_LENGTH,
                VALUE_LENGTH,
                [u8; TAG_LENGTH],
            >>::insert(vera, dx_new.clone()))?;

        // Retries upserting with the current EDX state until it succeeds.
        while !edx_cur.is_empty() {
            moved_id = Some(
                dx_cur.get(&tags[0]).ok_or_else(|| {
                    Error::<InMemoryDbError>::Crypto(
                        "current DX received does not contain any value for the upserted tag"
                            .to_string(),
                    )
                })?[0],
            );
            (dx_cur, edx_cur) = block_on(vera.upsert(edx_cur, dx_new.clone()))?;
        }

        if let Some(moved_id) = moved_id {
            // Moves the replaced ID to the next tag.
            concurrent_worker_upserter(vera, &tags[1..], moved_id)
        } else {
            Ok(())
        }
    }

    /// Tries concurrently upserting `N_WORKERS` IDs on the same sequence of
    /// tokens. Each worker first tries inserting its ID in the first tag of the
    /// pool. Upon failure, it tries replacing the current I with its ID, and
    /// moving the current ID to the next tag of the pool.
    ///
    /// Then verifies each worker ID were successfully inserted.
    #[test]
    fn test_concurrent_upsert() {
        let mut rng = CsRng::from_entropy();
        let db = InMemoryDb::default();
        let seed = Secret::<32>::random(&mut rng);

        // Generate a pool of tags, one tag per worker.
        let tags = (0..N_WORKERS)
            .map(|_| {
                let mut tag = [0; TAG_LENGTH];
                rng.fill_bytes(&mut tag);
                tag
            })
            .collect::<Vec<_>>();

        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                let seed = seed.clone();
                let tags = tags.clone();
                spawn(move || -> Result<(), Error<InMemoryDbError>> {
                    let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();
                    concurrent_worker_upserter(&vera, tags.as_slice(), i as u8)
                })
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();

        let dx = block_on(vera.dump()).unwrap();
        let stored_ids = dx.values().copied().collect::<HashSet<Item>>();
        assert_eq!(
            stored_ids,
            (0..N_WORKERS as u8)
                .map(|id| [id])
                .collect::<HashSet<Item>>()
        );
    }
}
