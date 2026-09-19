use std::ffi::{CStr, CString, c_void};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

#[repr(C)]
pub struct CliproxyBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

type HostCall =
    unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize, *mut CliproxyBuffer) -> i32;
type HostFree = unsafe extern "C" fn(*mut c_void, usize);

#[repr(C)]
pub struct CliproxyHostApi {
    pub abi_version: u32,
    pub host_ctx: *mut c_void,
    pub call: Option<HostCall>,
    pub free_buffer: Option<HostFree>,
}

static HOST_PTR: AtomicUsize = AtomicUsize::new(0);

pub fn install(host: *const CliproxyHostApi) {
    HOST_PTR.store(host as usize, Ordering::Release);
}

pub fn request(method: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    let address = HOST_PTR.load(Ordering::Acquire);
    if address == 0 {
        return Err("CPA host API is not initialized".to_owned());
    }

    let host = unsafe { &*(address as *const CliproxyHostApi) };
    let call = host
        .call
        .ok_or_else(|| "CPA host call is unavailable".to_owned())?;
    let method = CString::new(method).map_err(|_| "method contains NUL".to_owned())?;

    let mut response = CliproxyBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let rc = unsafe {
        call(
            host.host_ctx,
            method.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            &mut response,
        )
    };

    let bytes = if response.ptr.is_null() || response.len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(response.ptr, response.len) }.to_vec()
    };

    if !response.ptr.is_null()
        && let Some(free) = host.free_buffer
    {
        unsafe { free(response.ptr.cast::<c_void>(), response.len) };
    }

    if rc != 0 && bytes.is_empty() {
        return Err(format!("CPA host call {method:?} failed with code {rc}"));
    }
    Ok(bytes)
}

pub fn request_json(method: &str, payload: &Value) -> Result<Value, String> {
    let raw = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
    let response = request(method, &raw)?;
    let envelope: Value = serde_json::from_slice(&response).map_err(|error| {
        format!(
            "CPA host {method} returned invalid JSON: {error}: {}",
            String::from_utf8_lossy(&response)
        )
    })?;
    if envelope.get("ok").and_then(Value::as_bool) != Some(true) {
        let message = envelope
            .pointer("/error/message")
            .and_then(Value::as_str)
            .or_else(|| envelope.get("error").and_then(Value::as_str))
            .unwrap_or("unknown CPA host error");
        // Keep the machine-readable code in front of the message: callers make
        // policy decisions on the code, not on wording the host may reword.
        return Err(
            match envelope.pointer("/error/code").and_then(Value::as_str) {
                Some(code) => format!("{code}: {message}"),
                None => message.to_owned(),
            },
        );
    }
    Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
}

pub fn method_c_str(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("method is required".to_owned());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| "method is not UTF-8".to_owned())
}
