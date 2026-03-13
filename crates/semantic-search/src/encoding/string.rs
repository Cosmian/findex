// use super::*;
// use crate::Error;
// use cosmian_crypto_core::bytes_ser_de::Serializable;
// use cosmian_findex::{generic_decode, generic_encode};
// use zstd::bulk::{compress, decompress};

// fn bytes_to_chunks<const CHUNK_LENGTH: usize>(bytes: &[u8]) -> Vec<[u8; CHUNK_LENGTH]> {
//     assert!(CHUNK_LENGTH < 256);
//     let q = bytes.len() / CHUNK_LENGTH;
//     let r = bytes.len() % CHUNK_LENGTH;
//     let mut chunks = Vec::with_capacity(q + if r == 0 { 0 } else { 1 });
//     for i in 0..q {
//         chunks.push(
//             <[u8; CHUNK_LENGTH]>::try_from(&bytes[i * CHUNK_LENGTH..(i + 1) * CHUNK_LENGTH])
//                 .unwrap(),
//         );
//     }
//     let mut rest = [r as u8; CHUNK_LENGTH];
//     rest[1..=r].copy_from_slice(&bytes[q * CHUNK_LENGTH..]);
//     chunks.push(rest);
//     chunks
// }

// fn bytes_from_chunks<const CHUNK_LENGTH: usize>(chunks: &[[u8; CHUNK_LENGTH]]) -> Vec<u8> {
//     todo!()
// }

// /// An encoding that allows converting string of bound length into
// /// fixed-length chunks of bytes.
// pub struct StringEncoder<const MAX_STRING_LENGTH: usize, const CHUNK_LENGTH: usize>;

// impl<const MAX_STRING_LENGTH: usize, const CHUNK_LENGTH: usize> Encoding
//     for StringEncoder<MAX_STRING_LENGTH, CHUNK_LENGTH>
// {
//     type Value = String;

//     type Chunk = [u8; CHUNK_LENGTH];

//     type Error = Error;

//     fn encode(op: Op, values: HashSet<Self::Value>) -> Result<Vec<Self::Chunk>, Self::Error> {
//         generic_encode::<CHUNK_LENGTH, Vec<u8>>(
//             Op::Insert,
//             HashSet::from_iter([compress(&*Serializable::serialize(&(op, values))?, 0)
//                 .map_err(|e| Error(e.to_string()))?]),
//         )
//         .map_err(Error)
//     }

//     fn decode(chunks: Vec<Self::Chunk>) -> Result<HashSet<Self::Value>, Self::Error> {
//         let bytes = generic_decode::<CHUNK_LENGTH, _, Vec<u8>>(chunks)
//             .map_err(Error)?
//             .into_iter()
//             .next()
//             .ok_or_else(|| Error("could not read from the given bytes".to_string()))?;
//         let values = <HashSet<(Op, Self::Value)>>::deserialize(
//             &decompress(&bytes, MAX_STRING_LENGTH).map_err(|e| Error(e.to_string()))?,
//         )?;
//         let mut set = HashSet::with_capacity(values.len());
//         values.into_iter().for_each(|(op, v)| {
//             match op {
//                 Op::Insert => set.insert(v),
//                 Op::Delete => set.remove(&v),
//             };
//         });
//         Ok(set)
//     }
// }

// #[cfg(test)]
// use cosmian_crypto_core::reexport::rand_core::RngCore;

// #[test]
// fn test_string_encoding() {
//     use rand::{RngCore, rngs::ThreadRng};

//     const MAX_STRING_LENGTH: usize = 1024;

//     fn gen_val(rng: &mut CsRng) -> String {
//         let length = rng.next_u32() as usize % MAX_STRING_LENGTH;
//         let mut bytes = vec![0; length];
//         rng.fill_bytes(&mut bytes);
//         String::from_utf8_lossy(&bytes).to_string()
//     }
//     let mut rng = ThreadRng::default();
//     let mut seed = [0; 32];
//     rng.fill_bytes(&mut seed);
//     test_encoding::<StringEncoder<MAX_STRING_LENGTH, 128>>(seed, gen_val);
// }
