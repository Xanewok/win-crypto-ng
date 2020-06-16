use doc_comment::doctest;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::ntstatus;

use std::num::NonZeroU32;
use std::fmt;

// pub mod aead;
pub mod agreement;
pub mod asymmetric;
pub mod buffer;
pub mod handle;
pub mod hash;
pub mod key;
pub mod property;
pub mod random;
pub mod signature;
pub mod symmetric;

pub mod helpers;

// Compile and test the README
doctest!("../README.md");

/// Error type
///
/// These errors are a subset of [`NTSTATUS`](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).
/// Only the values used by CNG are part of this enum.
#[derive(Clone, Copy, Debug, PartialOrd, PartialEq)]
pub enum Error {
    NotFound,
    InvalidParameter,
    InvalidSignature,
    NoMemory,
    BufferTooSmall,
    InvalidHandle,
    NotSupported,
    AuthTagMismatch,
    InvalidBufferSize,
    Unsuccessful,
    RequestOutOfSequence,

    BadData,

    Unknown(NTSTATUS),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

impl Error {
    fn check(status: NTSTATUS) -> Result<()> {
        match status {
            ntstatus::STATUS_SUCCESS => Ok(()),
            ntstatus::STATUS_NOT_FOUND => Err(Error::NotFound),
            ntstatus::STATUS_INVALID_PARAMETER => Err(Error::InvalidParameter),
            ntstatus::STATUS_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
            ntstatus::STATUS_INVALID_HANDLE => Err(Error::InvalidHandle),
            ntstatus::STATUS_INVALID_SIGNATURE => Err(Error::InvalidSignature),
            ntstatus::STATUS_NOT_SUPPORTED => Err(Error::NotSupported),
            ntstatus::STATUS_AUTH_TAG_MISMATCH => Err(Error::AuthTagMismatch),
            ntstatus::STATUS_INVALID_BUFFER_SIZE => Err(Error::InvalidBufferSize),
            ntstatus::STATUS_REQUEST_OUT_OF_SEQUENCE =>Err(Error::RequestOutOfSequence),
            ntstatus::STATUS_NO_MEMORY | winapi::shared::winerror::NTE_NO_MEMORY => {
                Err(Error::NoMemory)
            }
            ntstatus::STATUS_DATA_ERROR | winapi::shared::winerror::NTE_BAD_DATA => {
                Err(Error::BadData)
            }
            ntstatus::STATUS_UNSUCCESSFUL => Err(Error::Unsuccessful),
            value => Err(Error::Unknown(value)),
        }
    }
}

impl Into<NonZeroU32> for Error {
    fn into(self) -> NonZeroU32 {
        let code: i32 = match self {
            Error::NotFound => ntstatus::STATUS_NOT_FOUND,
            Error::InvalidParameter => ntstatus::STATUS_INVALID_PARAMETER,
            Error::BufferTooSmall => ntstatus::STATUS_BUFFER_TOO_SMALL,
            Error::InvalidHandle => ntstatus::STATUS_INVALID_HANDLE,
            Error::InvalidSignature => ntstatus::STATUS_INVALID_SIGNATURE,
            Error::NotSupported => ntstatus::STATUS_NOT_SUPPORTED,
            Error::AuthTagMismatch => ntstatus::STATUS_AUTH_TAG_MISMATCH,
            Error::InvalidBufferSize => ntstatus::STATUS_INVALID_BUFFER_SIZE,
            Error::RequestOutOfSequence => ntstatus::STATUS_REQUEST_OUT_OF_SEQUENCE,
            Error::NoMemory=> ntstatus::STATUS_NO_MEMORY,
            Error::BadData=> ntstatus::STATUS_DATA_ERROR,
            Error::Unsuccessful => ntstatus::STATUS_UNSUCCESSFUL,
            Error::Unknown(value) => value,
        };

        NonZeroU32::new(code.abs() as u32).expect("Error to not be STATUS_SUCCESS")
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
