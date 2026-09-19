//! CLIProxyAPI dynamic-library plugin.
//!
//! The plugin keeps state in memory per selected CPA credential and model. The
//! credential is identified by `selected_auth_id` after auth selection, so a
//! state value is never shared across accounts.

mod abi;
mod host;
mod modeltrace;
mod runtime;

pub use abi::cliproxy_plugin_init;
