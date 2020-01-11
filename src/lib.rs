#![forbid(unsafe_code)]

#[macro_use]
extern crate async_trait;
#[macro_use]
extern crate derive_more;
#[cfg(feature = "serialize")]
#[macro_use]
extern crate serde_derive;

mod dns;
pub use dns::*;

#[cfg(fuzzing)]
pub mod fuzz;