use std::{
    cell::RefCell,
    convert::TryFrom,
    ffi::CString,
    os::raw::{c_char, c_int},
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FfiErr {
    #[error("Invalid NULL pointer passed for: {0}")]
    NullPointer(String),
    #[error("FFI error: {0}")]
    Generic(String),
}

/// Return early with an error if a pointer is null
///
/// This macro is equivalent to
///  `
/// if ptr.is_null() {
///     set_last_error(FfiErr::NullPointer($msg));
///     return 1;
/// }
/// `.
#[macro_export]
macro_rules! ffi_not_null {
    ($ptr:expr, $msg:literal $(,)?) => {
        if $ptr.is_null() {
            $crate::interfaces::ffi::error::set_last_error(
                $crate::interfaces::ffi::error::FfiErr::NullPointer($msg.to_owned()),
            );
            return 1_i32;
        }
    };
}

/// Unwrap a `std::result::Result`
///
/// If the result is in error, set the last error to its error and return 1
#[macro_export]
macro_rules! ffi_unwrap {
    ($result:expr, $msg:literal $(,)?) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiErr::Generic(format!("{}: {}", $msg, e)),
                );
                return 1_i32;
            }
        }
    };
    ($result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiErr::Generic(format!("{}", e)),
                );
                return 1_i32;
            }
        }
    };
}

/// Return early with an error if a condition is not satisfied.
#[macro_export]
macro_rules! ffi_bail {
    ($msg:literal $(,)?) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiErr::Generic($msg.to_owned()));
        return 1_i32;
    };
    ($err:expr $(,)?) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiErr::Generic($err.to_string()));
        return 1_i32;
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiErr::Generic(format!($fmt, $($arg)*)));
        return 1_i32;
    };
}

thread_local! {
    /// a thread-local variable which holds the most recent error
    static LAST_ERROR: RefCell<Option<Box<FfiErr>>> = RefCell::new(None);
}

/// Set the most recent error, clearing whatever may have been there before.
pub fn set_last_error(err: FfiErr) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

/// Get the most recent error as utf-8 bytes, clearing it in the process.
/// # Safety
/// - `error_msg`: must be pre-allocated with a sufficient size
#[no_mangle]
pub unsafe extern "C" fn get_last_error(
    error_msg_ptr: *mut c_char,
    error_len: *mut c_int,
) -> c_int {
    if error_msg_ptr.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated buffer");
        return 1;
    }
    if error_len.is_null() {
        eprintln!("get_last_error: must pass a pre-allocated len with the max buffer length");
        return 1;
    }
    if *error_len < 1 {
        eprintln!("get_last_error: the buffer must be at leas one byte long");
        return 1;
    }
    let err = LAST_ERROR.with(|prev| prev.borrow_mut().take());

    // Build a CString that will cleanup NULL bytes in the middle if needed
    let cs = ffi_unwrap!(
        CString::new(err.map_or(String::new(), |e| e.to_string())),
        "failed to convert error to CString"
    );
    // the CString as bytes
    let bytes = cs.as_bytes();

    // leave a space for a null byte at the end if the string exceeds the buffer
    // The actual bytes size, not taking into account the final NULL
    let error_len_cast = match usize::try_from(*error_len) {
        Ok(length) => length,
        Err(e) => {
            eprintln!("get_last_error: cast error length to `usize` failed: {e}");
            return 1;
        }
    };
    let actual_len = std::cmp::min(error_len_cast - 1, bytes.len());

    // create a 0 initialized vector with the message
    let mut result = vec![0; error_len_cast];
    {
        let (left, _right) = result.split_at_mut(actual_len);
        left.copy_from_slice(&bytes[0..actual_len]);
    }

    //copy the result in the OUT array
    std::slice::from_raw_parts_mut(error_msg_ptr.cast::<u8>(), error_len_cast)
        .copy_from_slice(&result);

    let actual_len_cast = match i32::try_from(actual_len) {
        Ok(length) => length,
        Err(e) => {
            eprintln!("get_last_error: cast actual length to `i32` failed: {e}");
            return 1;
        }
    };
    *error_len = actual_len_cast;
    0
}
