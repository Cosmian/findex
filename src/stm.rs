pub trait Stm {
    /// Address space.
    type Address;

    /// Word space.
    type Word;

    /// Memory error.
    type Error: std::error::Error;

    /// Reads the words bound to the given addresses.
    fn batch_read(
        &self,
        a: Vec<Self::Address>,
    ) -> Result<Vec<(Self::Address, Option<Self::Word>)>, Self::Error>;

    /// Adds the given memory bindings if the guard binding is stored.
    /// Returns the value of the guarded word after the writes.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error>;
}
