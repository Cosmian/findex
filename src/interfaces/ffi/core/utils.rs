use std::{convert::TryFrom, ffi::c_uchar};

use cosmian_crypto_core::symmetric_crypto::Dem;

use super::callbacks::FetchEntryTableCallback;
use crate::{
    core::Keyword,
    error::FindexErr,
    interfaces::{
        ffi::{core::ErrorCode, LEB128_MAXIMUM_ENCODED_BYTES_NUMBER},
        generic_parameters::{DemScheme, BLOCK_LENGTH, KWI_LENGTH, TABLE_WIDTH, UID_LENGTH},
    },
};

/// Makes sure the given callback exists in the given Findex instance.
///
/// - `findex`      : name of the findex instance
/// - `callback`    : name of the callback
macro_rules! unwrap_callback {
    ($findex:ident, $callback:ident) => {
        $findex.$callback.as_ref().ok_or_else(|| {
            FindexErr::CryptoError(format!(
                "No attribute `{}` is defined for `self`",
                stringify!($callback)
            ))
        })?
    };
}

/// Returns an upper-bound on the size of a serialized encrypted Entry Table.
///
/// An Entry Table line is composed of:
/// - the Entry Table UID;
/// - the `Kwi`;
/// - the Chain Table UID;
/// - the `Keyword` hash.
///
/// Therefore the serialized encrypted Entry Table looks like:
///
/// `| LEB128(table.len()) | UID1 | LEB128(encrypted_value1.len()) |
/// encrypted_value1 | ...`
///
/// where the size of an encrypted value is:
///
/// `ENCRYPTION_OVERHEAD + KWI_LENGTH + UID_LENGTH + KEYWORD_HASH_LENGTH`
///
/// # Arguments
/// - `line_number` : number of lines in the encrypted Entry Table
/// - `entry_table_number` : number of different entry tables. The number is
///   required here since severable entry table could give multiple results
pub const fn get_serialized_encrypted_entry_table_size_bound(
    line_number: usize,
    entry_table_number: usize,
) -> usize {
    LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
        + line_number
            * entry_table_number
            * (UID_LENGTH
                + LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
                + DemScheme::ENCRYPTION_OVERHEAD
                + KWI_LENGTH
                + UID_LENGTH
                + Keyword::HASH_LENGTH)
}

/// Returns an upper-bound on the size of a serialized encrypted Chain Table.
///
/// A Chain Table line is composed of:
/// - the Chain Table UID;
/// - `TABLE_WIDTH` blocks of length `BLOCK_LENGTH`
///
/// Therefore the serialized encrypted Entry Table looks like:
///
/// `| LEB128(table.len()) | UID1 | LEB128(encrypted_value1.len()) |
/// encrypted_value1 | ...`
///
/// where the size of an encrypted value is:
///
/// `ENCRYPTION_OVERHEAD + TABLE_WIDTH * BLOCK_LENGTH`
///
/// # Arguments
/// - `line_number` : number of lines in the encrypted Entry Table
pub const fn get_allocation_size_for_select_chain_request(line_number: usize) -> usize {
    LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
        + line_number * UID_LENGTH
        + line_number
            * (LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
                + DemScheme::ENCRYPTION_OVERHEAD
                + TABLE_WIDTH * BLOCK_LENGTH)
}

/// Call the given fetch callback.
///
/// - `uids`            : UIDs to fetch (callback input)
/// - `allocation_size` : size needed to be allocated for the output
/// - `callback`        : fetch callback
pub fn fetch_callback(
    uids: &[u8],
    allocation_size: usize,
    callback: FetchEntryTableCallback,
    debug_name: &'static str,
) -> Result<Vec<u8>, FindexErr> {
    //
    // DB request with correct allocation size
    //
    let mut output_bytes = vec![0_u8; allocation_size];
    let mut output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
    let mut output_len = u32::try_from(allocation_size)?;

    let mut error_code = callback(
        output_ptr,
        &mut output_len,
        uids.as_ptr(),
        u32::try_from(uids.len())?,
    );

    if error_code == ErrorCode::BufferTooSmall as i32 {
        output_bytes = vec![0_u8; output_len as usize];
        output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();

        error_code = callback(
            output_ptr,
            &mut output_len,
            uids.as_ptr(),
            u32::try_from(uids.len())?,
        );
    }

    if error_code != ErrorCode::Success as i32 {
        return Err(FindexErr::CallbackErrorCode {
            name: debug_name,
            code: error_code,
        });
    }

    if output_len == 0 {
        return Ok(vec![]);
    }

    //
    // Recopy buffer in Vec<u8>
    //
    let output_entries_bytes = unsafe {
        std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize).to_vec()
    };
    Ok(output_entries_bytes)
}
