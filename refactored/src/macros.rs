pub use tiny_keccak::{self, Hasher, IntoXof, Kmac, KmacXof, Xof};

/// Hashes the given bytes to the desired length using the KMAC algorithm and
/// the given key.
///
/// - `length`  : length of the generated output
/// - `key`     : KMAC key
/// - `bytes`   : bytes to hash
#[macro_export]
macro_rules! kmac {
    ($length: ident, $key: expr, $($bytes: expr),+) => {
        {
            let mut kmac = $crate::macros::tiny_keccak::Kmac::v256($key, b"");
            $(
                <$crate::macros::Kmac as $crate::macros::Hasher>::update(&mut kmac, $bytes);
            )*
            let mut xof = <$crate::macros::Kmac as $crate::macros::IntoXof>::into_xof(kmac);
            let mut res = [0; $length];
            <$crate::macros::KmacXof as $crate::macros::Xof>::squeeze(&mut xof, &mut res);
            res
        }
    };
}
