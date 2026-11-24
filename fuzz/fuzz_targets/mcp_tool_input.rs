#![no_main]

//! Fuzzes every MCP tool input parser with arbitrary JSON.
//!
//! Each input is fed unchanged to a representative set of tools through the
//! pure `parse_mcp_tool_input` entry point, which runs the same `serde_json`
//! decode (`deny_unknown_fields`) and value checks as dispatch. Only the
//! "never panic" property is checked.

use dnscraft_mcp::parse_mcp_tool_input;
use libfuzzer_sys::fuzz_target;

const TOOLS: [&str; 16] = [
    "search_query_log",
    "get_query",
    "explain_block",
    "test_query",
    "get_stats",
    "list_clients",
    "get_status",
    "list_mcp_rules",
    "diagnose",
    "network_health",
    "list_mcp_proposals",
    "allow_temporarily",
    "add_rule",
    "remove_rule",
    "pause_filter_set",
    "resume_filter_set",
];

fuzz_target!(|data: &[u8]| {
    for tool in TOOLS {
        let _ = parse_mcp_tool_input(tool, data);
    }
});
