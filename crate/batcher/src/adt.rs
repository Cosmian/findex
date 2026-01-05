use std::{collections::HashSet, future::Future};

/// This trait provides methods that let an index operate on multiple keywords
/// or entries simultaneously.
pub trait IndexBatcher<Keyword, Value> {
    type Error: std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> impl Future<Output = Result<Vec<HashSet<Value>>, Self::Error>>;

    /// Binds each value to their associated keyword in this index.
    fn batch_insert<Values, Entries>(
        &self,
        entries: Entries,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>
    where
        Values: Send + IntoIterator<Item = Value>,
        Entries: Send + IntoIterator<Item = (Keyword, Values)>,
        Entries::IntoIter: ExactSizeIterator,
        <Entries as IntoIterator>::IntoIter: Send;

    /// Removes the given values from the index.
    fn batch_delete<Values, Entries>(
        &self,
        entries: Entries,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>
    where
        Values: Send + IntoIterator<Item = Value>,
        Entries: Send + IntoIterator<Item = (Keyword, Values)>,
        Entries::IntoIter: ExactSizeIterator + Send;
}
