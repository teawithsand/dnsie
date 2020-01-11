//! dns module implements DNS resolvers - modules able to translate domain into IP address and vice versa

// TODO(teawithsand): clean up this reexport mess
pub use common::*;
pub use packet::primitives::*;

mod common;
pub(crate) mod packet;

#[cfg(feature = "doh")]
pub mod doh;
/*
#[cfg(feature = "c")]
pub mod libc;
*/