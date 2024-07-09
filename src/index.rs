use std::{fmt::Display, hash::Hash};

use tracing::{instrument, trace};

use crate::{
    CoreError, CsMmEnc, Dx, EdxDbInterface, Findex, Link, Metadata, Mm, Set, Tag, Vera,
    MIN_SEED_LENGTH,
};

use cosmian_crypto_core::{kdf256, Secret};

/// Key used to instantiate an [`Index`](Index).
pub type UserKey = Secret<MIN_SEED_LENGTH>;

/// Error used in [`Index`](Index) operations.
pub type IndexError<EntryDbConnection, ChainDbConnection> = <Findex<
    { Tag::LENGTH },
    Vera<{ Metadata::LENGTH }, EntryDbConnection, Metadata>,
    Vera<{ Link::LENGTH }, ChainDbConnection, Link>,
> as CsMmEnc>::Error;

/// Easy to use interface for [`Findex`](Findex) that hides most cryptographic details.
///
/// Uses [`Findex`](Findex) with two instances of [`Vera`](Vera) as Entry and Chain DX-Enc.
pub struct Index<EntryDbConnection: EdxDbInterface, ChainDbConnection: EdxDbInterface>(
    Findex<
        { Tag::LENGTH },
        Vera<{ Metadata::LENGTH }, EntryDbConnection, Metadata>,
        Vera<{ Link::LENGTH }, ChainDbConnection, Link>,
    >,
);

impl<EntryDbConnection: EdxDbInterface, ChainDbConnection: EdxDbInterface>
    Index<EntryDbConnection, ChainDbConnection>
{
    /// Instantiates an index using the given key and DB connections.
    pub fn new(
        key: &UserKey,
        entry_connection: EntryDbConnection,
        chain_connection: ChainDbConnection,
    ) -> Result<Self, IndexError<EntryDbConnection, ChainDbConnection>> {
        Findex::setup(key, (entry_connection, chain_connection)).map(Self)
    }

    /// Search for data bound to the given keywords.
    #[instrument(ret(Display), err, skip_all)]
    pub async fn search<
        Keyword: Hash + PartialEq + Eq + AsRef<[u8]> + Display,
        Data: Display + From<Vec<u8>>,
    >(
        &self,
        keywords: Set<Keyword>,
    ) -> Result<Mm<Keyword, Data>, IndexError<EntryDbConnection, ChainDbConnection>> {
        trace!("search: entering: keywords: {keywords}");
        let mut tag2kw: Dx<Tag, Keyword> = keywords
            .into_iter()
            .map(|kw| {
                let mut tag = Tag::default();
                kdf256!(&mut tag, kw.as_ref());
                (tag, kw)
            })
            .collect();
        let res = self.0.search(tag2kw.keys().copied().collect()).await?;
        res.into_iter()
            .map(|(tag, values)| {
                tag2kw
                    .remove(&tag)
                    .ok_or_else(|| CoreError::Crypto("missing keyword".to_string()))
                    .map(|kw| (kw, values.into_iter().map(Data::from).collect()))
            })
            .collect::<Result<_, _>>()
            .map_err(IndexError::<EntryDbConnection, ChainDbConnection>::from)
    }

    /// Adds the given bindings to the index.
    #[instrument(err, skip_all)]
    pub async fn add<
        Keyword: Hash + PartialEq + Eq + AsRef<[u8]> + Display,
        Data: Display + Into<Vec<u8>>,
    >(
        &self,
        bindings: Mm<Keyword, Data>,
    ) -> Result<(), IndexError<EntryDbConnection, ChainDbConnection>> {
        trace!("add: entering: additions: {bindings}");
        self.0
            .insert(
                bindings
                    .into_iter()
                    .map(|(kw, data)| {
                        let mut tag = Tag::default();
                        kdf256!(&mut tag, kw.as_ref());
                        let values = data.into_iter().map(Data::into).collect();
                        (tag, values)
                    })
                    .collect(),
            )
            .await
    }

    /// Deletes the given bindings from the index.
    #[instrument(err, skip_all)]
    pub async fn delete<
        Keyword: Hash + PartialEq + Eq + AsRef<[u8]> + Display,
        Data: Display + Into<Vec<u8>>,
    >(
        &self,
        bindings: Mm<Keyword, Data>,
    ) -> Result<(), IndexError<EntryDbConnection, ChainDbConnection>> {
        trace!("delete: entering: deletions: {bindings}");
        self.0
            .delete(
                bindings
                    .into_iter()
                    .map(|(kw, data)| {
                        let mut tag = Tag::default();
                        kdf256!(&mut tag, kw.as_ref());
                        let values = data.into_iter().map(Data::into).collect();
                        (tag, values)
                    })
                    .collect(),
            )
            .await
    }

    /// Compacts the current index: rewrites all chains without inner padding.
    ///
    /// This operation is concurrent-safe.
    #[instrument(ret, err, skip_all)]
    pub async fn compact(&self) -> Result<(), IndexError<EntryDbConnection, ChainDbConnection>> {
        self.0.compact().await
    }

    /// The rebuild operation allows changing the key. It re-encrypts the index
    /// using the given key, and stores it using the given connections.
    ///
    /// Any concurrent modification may be lost during the rebuild
    /// operation. Acquiring a lock on the current index may be needed
    /// before rebuilding it.
    #[instrument(err, skip_all)]
    pub async fn rebuild(
        &self,
        key: &UserKey,
        entry_connection: EntryDbConnection,
        chain_connection: ChainDbConnection,
    ) -> Result<Self, IndexError<EntryDbConnection, ChainDbConnection>> {
        self.0
            .rebuild(key, (entry_connection, chain_connection))
            .await
            .map(Self)
    }
}
