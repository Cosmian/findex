use std::marker::PhantomData;

use cosmian_crypto_core::{kdf256, Secret};

use crate::{CoreError, DbInterface, Error, MIN_SEED_LENGTH};

use super::{
    primitives::{Dem, Kmac},
    CsRhDxEnc, Dx, DynRhDxEnc, Edx, Set, Tag, Token,
};

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
    fn tokenize(&self, tag: &Tag) -> Token {
        self.kmac.hash(tag, Self::TOKEN_INFO).into()
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
                let ctx = self
                    .dem
                    .encrypt(&[&tag, val.into().as_slice()].concat(), &tok)?;
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
                if ptx.len() != Tag::LENGTH + VALUE_LENGTH {
                    Err(CoreError::Crypto(format!(
                        "invalid length for decrypted EDX value: expected {}, found {}",
                        Tag::LENGTH + VALUE_LENGTH,
                        ptx.len(),
                    )))
                } else {
                    let tag = Tag::try_from(&ptx[..Tag::LENGTH])?;
                    let val = <[u8; VALUE_LENGTH]>::try_from(&ptx[Tag::LENGTH..])
                        .expect("above check ensures length is correct");
                    Ok((tag, val.into()))
                }
            })
            .collect()
    }
}

impl<
        const VALUE_LENGTH: usize,
        DbConnection: DbInterface + Clone,
        Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
    > DynRhDxEnc<VALUE_LENGTH> for Vera<VALUE_LENGTH, DbConnection, Item>
{
    type Error = Error<DbConnection::Error>;
    type DbConnection = DbConnection;
    type Tag = Tag;
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

    async fn get(
        &self,
        tags: Set<Self::Tag>,
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

    async fn delete(&self, tags: Set<Self::Tag>) -> Result<(), Self::Error> {
        let tokens = tags.iter().map(|tag| self.tokenize(tag)).collect();
        self.connection
            .delete(tokens)
            .await
            .map_err(Self::Error::from)
    }

    async fn rebuild(&self, seed: &[u8], connection: DbConnection) -> Result<Self, Self::Error> {
        let edx = self.connection.dump().await?;
        let dx = self.resolve(&edx)?;
        let new_scheme = Self::setup(seed, connection)?;
	<Self as DynRhDxEnc<VALUE_LENGTH>>::insert(&new_scheme, dx).await?;
	Ok(new_scheme)
    }
}

impl<
        const VALUE_LENGTH: usize,
        DbConnection: DbInterface + Clone,
        Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>,
    > CsRhDxEnc<{ Tag::LENGTH }, VALUE_LENGTH, Tag> for Vera<VALUE_LENGTH, DbConnection, Item>
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
}

#[cfg(all(test, feature = "in_memory"))]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        thread::spawn,
    };

    use cosmian_crypto_core::CsRng;
    use futures::executor::block_on;
    use rand::SeedableRng;

    use crate::{InMemoryDb, InMemoryDbError};

    use super::*;

    const N_WORKERS: usize = 100;
    const VALUE_LENGTH: usize = 1;
    type Item = [u8; VALUE_LENGTH];

    /// Tries inserting `N_WORKERS` data using random tokens. Then verifies the
    /// inserted and fetched DX are identical.
    #[test]
    fn insert_then_dump_and_fetch() {
        let mut rng = CsRng::from_entropy();
        let db = InMemoryDb::default();
        let seed = Secret::<32>::random(&mut rng);
        let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();
        let inserted_dx = (0..N_WORKERS)
            .map(|i| {
                let tag = Tag::random(&mut rng);
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

        let fetched_dx = block_on(vera.get(inserted_dx.keys().copied().collect())).unwrap();
        assert_eq!(inserted_dx, *fetched_dx);
    }

    /// Implement a worker that upserts the given value for the first one of the
    /// given tags.
    ///
    /// Upon success, if a value was already inserted for this tag, inserts this
    /// value for the next tag using a recursive call.
    fn concurrent_worker_upserter(
        vera: &Vera<VALUE_LENGTH, InMemoryDb, Item>,
        tags: &[Tag],
        value: u8,
    ) -> Result<(), Error<InMemoryDbError>> {
        if tags.is_empty() {
            return Err(Error::Crypto(format!("could not insert {value}")));
        }
        let mut moved_value = None;
        let dx_new = Dx::from(HashMap::from_iter([(tags[0], [value])]));

        // First tries to insert the worker value for the first tag.
        let (mut dx_cur, mut edx_cur) =
            block_on(<Vera<VALUE_LENGTH, InMemoryDb, Item> as CsRhDxEnc<
                { Tag::LENGTH },
                VALUE_LENGTH,
                Tag,
            >>::insert(vera, dx_new.clone()))?;

        // Retries upserting with the current EDX state until it succeeds.
        while !edx_cur.is_empty() {
            moved_value = Some(
                dx_cur.get(&tags[0]).ok_or_else(|| {
                    Error::<InMemoryDbError>::Crypto(
                        "current DX received does not contain any value for the upserted tag"
                            .to_string(),
                    )
                })?[0],
            );
            (dx_cur, edx_cur) = block_on(vera.upsert(edx_cur, dx_new.clone()))?;
        }

        if let Some(value) = moved_value {
            // Moves the replaced value to the next tag.
            concurrent_worker_upserter(vera, &tags[1..], value)
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
    fn concurrent_upsert() {
        let mut rng = CsRng::from_entropy();
        let db = InMemoryDb::default();
        let seed = Secret::<32>::random(&mut rng);

        // Generate a pool of tags, one tag per worker.
        let tags = (0..N_WORKERS)
            .map(|_| Tag::random(&mut rng))
            .collect::<Vec<_>>();

        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                let seed = seed.clone();
                let tags = tags.clone();
                spawn(move || -> Result<(), Error<InMemoryDbError>> {
                    let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();
                    concurrent_worker_upserter(&vera, &tags, i as u8)
                })
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let vera = Vera::<VALUE_LENGTH, InMemoryDb, Item>::setup(&*seed, db).unwrap();
        let stored_dx = block_on(vera.get(tags.into_iter().collect())).unwrap();
        let stored_ids = stored_dx.values().copied().collect::<HashSet<Item>>();
        assert_eq!(
            stored_ids,
            (0..N_WORKERS as u8)
                .map(|id| [id])
                .collect::<HashSet<Item>>()
        );
    }
}
