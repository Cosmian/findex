use std::collections::HashSet;

use cosmian_crypto_core::bytes_ser_de::Serializable;
use js_sys::{Array, Object, Reflect, Uint8Array};
pub use js_sys::{Function, Promise};
pub use wasm_bindgen::JsValue;

use crate::{
    core::{EncryptedTable, Uid},
    error::FindexErr,
    interfaces::wasm_bindgen::core::types::Fetch,
};

/// Call the WASM callback.
macro_rules! callback {
    ($callback_ref:expr, $input:ident) => {{
        let this = &$crate::interfaces::wasm_bindgen::core::utils::JsValue::null();
        let js_function = $crate::interfaces::wasm_bindgen::core::utils::Function::from(
            $crate::interfaces::wasm_bindgen::core::utils::JsValue::from($callback_ref),
        );
        let promise = $crate::interfaces::wasm_bindgen::core::utils::Promise::resolve(
            &js_function
                .call1(this, &$input)
                .map_err(|e| FindexErr::CallBack(format!("Failed to call callback: {e:?}")))?,
        );
        wasm_bindgen_futures::JsFuture::from(promise)
            .await
            .map_err(|e| {
                FindexErr::CallBack(format!("Failed while waiting for `$callback_name`: {e:?}"))
            })
    }};
}

/// Makes sure the given callback exists in the given Findex instance.
///
/// - `findex`      : name of the findex instance
/// - `callback`    : name of the callback
macro_rules! unwrap_callback {
    ($findex:ident, $callback:ident) => {
        $findex.$callback.as_ref().ok_or_else(|| {
            FindexErr::CryptoError("No attribute `$callback` is defined for `self`".to_string())
        })?
    };
}

/// Fetch all items matching the given uids.
///
/// - `uids`         : the uids to fetch
/// - `fetch_entries`: JS callback calling the DB
#[inline]
pub async fn fetch_uids<const UID_LENGTH: usize>(
    uids: &HashSet<Uid<UID_LENGTH>>,
    fetch_callback: &Fetch,
) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
    // Convert Inputs to array of Uint8Array
    let input = Array::new();
    for uid in uids {
        let js_uid = unsafe { Uint8Array::new(&Uint8Array::view(uid)) };
        input.push(&js_uid);
    }

    // perform the call
    let output = callback!(fetch_callback, input)?;

    // parse results into HashMap
    js_value_to_encrypted_table(&output).map_err(|e| {
        FindexErr::CallBack(format!(
            "Failed to convert JsValue into `EncryptedTable`: {e:?}"
        ))
    })
}

#[inline]
pub fn set_bytes_in_object_property(
    obj: &JsValue,
    property: &str,
    value: Option<&[u8]>,
) -> Result<bool, JsValue> {
    js_sys::Reflect::set(obj, &JsValue::from_str(property), unsafe {
        &value.map_or_else(JsValue::null, |bytes| {
            JsValue::from(Uint8Array::new(&Uint8Array::view(bytes)))
        })
    })
}

#[inline]
pub fn js_value_to_encrypted_table<const UID_LENGTH: usize>(
    encrypted_table: &JsValue,
) -> Result<EncryptedTable<UID_LENGTH>, JsValue> {
    let array = Array::from(encrypted_table);
    let mut encrypted_table = EncryptedTable::<UID_LENGTH>::with_capacity(array.length() as usize);
    for try_obj in array.values() {
        let obj = try_obj?;
        let uid = get_bytes_from_object_property(&obj, "uid")?;
        let value = get_bytes_from_object_property(&obj, "value")?;
        encrypted_table.insert(Uid::try_from_bytes(&uid)?, value.clone());
    }
    Ok(encrypted_table)
}

#[inline]
pub fn encrypted_table_to_js_value<const UID_LENGTH: usize>(
    encrypted_table: &EncryptedTable<UID_LENGTH>,
) -> Result<Array, JsValue> {
    let res = Array::new_with_length(encrypted_table.len() as u32);
    for (index, (uid, value)) in encrypted_table.iter().enumerate() {
        let obj = Object::new();
        set_bytes_in_object_property(&obj, "uid", Some(uid))?;
        set_bytes_in_object_property(&obj, "value", Some(value))?;
        res.set(index as u32, obj.into());
    }
    Ok(res)
}

#[inline]
pub fn get_bytes_from_object_property(obj: &JsValue, property: &str) -> Result<Vec<u8>, JsValue> {
    Ok(Uint8Array::from(Reflect::get(obj, &JsValue::from_str(property))?).to_vec())
}
