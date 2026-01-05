#![warn(clippy::all, clippy::nursery, clippy::cargo)]
#![allow(dead_code)]
#![allow(clippy::complexity)]

mod adt;
mod error;
mod index_batcher;

pub mod server_batcher;

pub trait ClientBatcher
where
    <Self::Interface as ClientServerADT>::ServerInterface: ServerBatcher,
{
    type Interface: ClientServerADT;
}

pub trait ServerBatcher: Clone + Send {
    type Srv;
    type Error: std::error::Error;
    fn new(interface: Self::Srv) -> Self;
    fn buffer_length(&self) -> usize;
    fn resize(&self, capacity: usize) -> Result<(), Self::Error>;
    fn shrink(&self) -> Result<(), Self::Error>;
}

pub trait ClientServerADT: Sized {
    type Error: std::error::Error;
    type ServerInterface;
    type ClientParameters;

    fn connect(
        cnx: Self::ServerInterface,
        params: Self::ClientParameters,
    ) -> Result<Self, Self::Error>;
}
