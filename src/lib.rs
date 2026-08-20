//! Waypad signaling server library.
//!
//! Exposed as a library so the end-to-end WebSocket flow can be exercised by
//! integration tests without shelling out to the binary.

pub mod auth;
pub mod protocol;
pub mod registry;
pub mod server;
