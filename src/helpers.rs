//! Facilitating abstractions for FFI usage.

pub mod bytes;
pub use bytes::{AsBytes, FromBytes};
pub mod blob;
pub use blob::{Blob, BlobLayout};
pub mod string;
pub use string::WideCString;
