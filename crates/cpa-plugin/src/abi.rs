use std::ffi::c_void;
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use serde_json::{Value, json};

use crate::host::{self, CliproxyBuffer, CliproxyHostApi};
use crate::runtime;

type PluginCall = unsafe extern "C" fn(*const c_char, *const u8, usize, *mut CliproxyBuffer) -> i32;
type PluginFree = unsafe extern "C" fn(*mut c_void, usize);
type PluginShutdown = unsafe extern "C" fn();

#[repr(C)]
pub struct CliproxyPluginApi {
    pub abi_version: u32,
    pub call: Option<PluginCall>,
    pub free_buffer: Option<PluginFree>,
    pub shutdown: Option<PluginShutdown>,
}

const ABI_VERSION: u32 = 1;
const SCHEMA_VERSION: u32 = 6;

#[unsafe(no_mangle)]
/// # Safety
/// The host must pass valid pointers to host and plugin API tables.
pub unsafe extern "C" fn cliproxy_plugin_init(
    host_api: *const CliproxyHostApi,
    plugin_api: *mut CliproxyPluginApi,
) -> i32 {
    if plugin_api.is_null() {
        return 1;
    }
    host::install(host_api);
    unsafe {
        (*plugin_api).abi_version = ABI_VERSION;
        (*plugin_api).call = Some(plugin_call);
        (*plugin_api).free_buffer = Some(plugin_free);
        (*plugin_api).shutdown = Some(plugin_shutdown);
    }
    runtime::start();
    0
}

unsafe extern "C" fn plugin_call(
    method: *const c_char,
    request: *const u8,
    request_len: usize,
    response: *mut CliproxyBuffer,
) -> i32 {
    if !response.is_null() {
        unsafe {
            (*response).ptr = ptr::null_mut();
            (*response).len = 0;
        }
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let method = host::method_c_str(method)?;
        let payload = if request.is_null() || request_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(request, request_len) }.to_vec()
        };
        dispatch(&method, &payload)
    }));

    let body = match result {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => error_envelope("plugin_error", &error),
        Err(_) => error_envelope("plugin_panic", "plugin panicked while handling request"),
    };
    write_response(response, body.as_bytes());
    0
}

fn dispatch(method: &str, payload: &[u8]) -> Result<String, String> {
    match method {
        "plugin.register" | "plugin.reconfigure" => Ok(registration().to_string()),
        "plugin.quiesce" | "plugin.shutdown" => {
            runtime::quiesce();
            Ok(ok_envelope(json!({})).to_string())
        }
        "request.intercept_before" => {
            Ok(ok_envelope(runtime::intercept_before(payload)?).to_string())
        }
        "request.intercept_after" => {
            Ok(ok_envelope(runtime::intercept_after_auth(payload)?).to_string())
        }
        "response.intercept_after" => {
            Ok(ok_envelope(runtime::intercept_response(payload)?).to_string())
        }
        "response.intercept_stream_chunk" => {
            Ok(ok_envelope(runtime::intercept_stream_chunk(payload)?).to_string())
        }
        "request.complete" => Ok(ok_envelope(runtime::complete_request(payload)?).to_string()),
        "management.register" => Ok(management_registration().to_string()),
        "management.handle" => Ok(ok_envelope(runtime::handle_management(payload)?).to_string()),
        _ => Ok(error_envelope("unknown_method", "unknown method").to_string()),
    }
}

fn registration() -> Value {
    ok_envelope(json!({
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "Name": "FixGPT",
            "Version": env!("CARGO_PKG_VERSION"),
            "Author": "Lingbou",
            "GitHubRepository": "https://github.com/Lingbou/FixGPT",
            "Logo": "",
            "ConfigFields": []
        },
        "capabilities": {
            "request_interceptor": true,
            "request_lifecycle_plugin": true,
            "response_interceptor": true,
            "response_stream_interceptor": true,
            "management_api": true
        }
    }))
}

fn management_registration() -> Value {
    ok_envelope(json!({
        "Resources": [
            {
                "Path": "/status",
                "Menu": "FixGPT",
                "Description": "FixGPT state, account, and turn-state overview."
            },
            {
                "Path": "/modeltrace/start",
                "Menu": "",
                "Description": ""
            },
            {
                "Path": "/modeltrace/status",
                "Menu": "",
                "Description": ""
            },
            {
                "Path": "/modeltrace/tasks",
                "Menu": "",
                "Description": ""
            },
            {
                "Path": "/injection",
                "Menu": "",
                "Description": ""
            },
            {
                "Path": "/harvest",
                "Menu": "",
                "Description": ""
            },
            {
                "Path": "/state",
                "Menu": "",
                "Description": ""
            }
        ],
        "Routes": []
    }))
}

fn ok_envelope(result: Value) -> Value {
    json!({ "ok": true, "result": result })
}

fn error_envelope(code: &str, message: &str) -> String {
    json!({
        "ok": false,
        "error": {
            "code": code,
            "message": message
        }
    })
    .to_string()
}

fn write_response(response: *mut CliproxyBuffer, bytes: &[u8]) {
    if response.is_null() {
        return;
    }
    let mut buffer = bytes.to_vec();
    let len = buffer.len();
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    unsafe {
        (*response).ptr = ptr;
        (*response).len = len;
    }
}

unsafe extern "C" fn plugin_free(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() {
        let _ = unsafe { Vec::from_raw_parts(ptr.cast::<u8>(), len, len) };
    }
}

unsafe extern "C" fn plugin_shutdown() {
    runtime::stop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_exposes_a_single_merged_menu() {
        let registration = management_registration();
        let resources = registration
            .pointer("/result/Resources")
            .and_then(Value::as_array)
            .expect("resources");
        let menus: Vec<&str> = resources
            .iter()
            .filter_map(|resource| {
                resource
                    .get("Menu")
                    .and_then(Value::as_str)
                    .filter(|menu| !menu.is_empty())
            })
            .collect();
        // 两个界面已合并：只保留一个菜单入口，避免重复。
        assert_eq!(menus, vec!["FixGPT"]);
    }
}
