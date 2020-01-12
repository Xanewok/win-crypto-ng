//! Cryptographically secure random number generation.
#![warn(missing_docs)]

use core::convert::TryFrom;
use core::fmt;
use core::ptr;

use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

use crate::helpers::{AlgoHandle, Handle};
use crate::Error;

/// An RNG algorithm provider. Main type that is capable of generating random
/// numbers.
pub enum RandomAlgorithm {
    /// System-preferred algorithm provider.
    SystemPreferred,
    /// An already opened provider for a specified algorithm.
    Specified(RandomAlgoHandle),
}

/// Wrapper around `AlgoHandle` that can only specify RNG algorithms.
pub struct RandomAlgoHandle(AlgoHandle);

/// Kind of a random algorithm to be used when generating numbers.
#[derive(Clone, Copy)]
pub enum RandomAlgorithmKind {
    /// Use the system-preferred random number generator algorithm.
    /// Implies setting `BCRYPT_USE_SYSTEM_PREFERRED_RNG` flag when calling
    /// `BCryptGenRandom`.
    ///
    /// This is only supported at `PASSIVE_LEVEL` IRQL. For more information,
    /// see [`Remarks`](https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom#remarks).
    /// *Windows Vista*:  This flag is not supported.
    SystemPreferred,
    /// Use the specified random number generator algorithm.
    Specified(RandomAlgorithmId),
}

/// Random number generation algorithms supported RNG algorithms by Windows CNG API.
#[derive(Clone, Copy)]
pub enum RandomAlgorithmId {
    /// The random-number generator algorithm.
    /// Standard: FIPS 186-2, FIPS 140-2, NIST SP 800-90
    ///
    /// Beginning with Windows Vista with SP1 and Windows Server 2008, the
    /// random number generator is based on the AES counter mode specified in
    /// the NIST SP 800-90 standard.
    ///
    /// *Windows Vista*: The random number generator is based on the hash-based
    /// random number generator specified in the FIPS 186-2 standard.
    ///
    /// *Windows 8*: Beginning with Windows 8, the RNG algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    RNG,
    /// The dual elliptic curve random-number generator algorithm.
    ///
    /// Standard: SP800-90.
    ///
    /// *Windows 8*: Beginning with Windows 8, the EC RNG algorithm supports
    /// FIPS 186-3. Keys less than or equal to 1024 bits adhere to FIPS 186-2
    /// and keys greater than 1024 to FIPS 186-3.
    ///
    /// *Windows 10*: Beginning with Windows 10, the dual elliptic curve random
    /// number generator algorithm has been removed. Existing uses of this
    /// algorithm will continue to work; however, the random number generator is
    /// based on the AES counter mode specified in the NIST SP 800-90 standard.
    /// New code should use `BCRYPT_RNG_ALGORITHM`, and it is recommended that
    /// existing code be changed to use `BCRYPT_RNG_ALGORITHM`.
    DUALECRNG,
    /// The random-number generator algorithm suitable for DSA (Digital
    /// Signature RandomAlgorithmId).
    ///
    /// Standard: FIPS 186-2.
    ///
    /// *Windows 8*: Support for FIPS 186-3 begins.
    FIPS186DSARNG,
}

impl Default for RandomAlgorithm {
    fn default() -> Self {
        RandomAlgorithm::SystemPreferred
    }
}

impl<'a> TryFrom<&'a str> for RandomAlgorithmId {
    type Error = &'a str;

    fn try_from(value: &'a str) -> Result<RandomAlgorithmId, Self::Error> {
        match value {
            BCRYPT_RNG_ALGORITHM => Ok(RandomAlgorithmId::RNG),
            BCRYPT_RNG_DUAL_EC_ALGORITHM => Ok(RandomAlgorithmId::DUALECRNG),
            BCRYPT_RNG_FIPS186_DSA_ALGORITHM => Ok(RandomAlgorithmId::FIPS186DSARNG),
            _ => Err(value),
        }
    }
}

impl Into<&'static str> for RandomAlgorithmId {
    fn into(self) -> &'static str {
        match self {
            RandomAlgorithmId::RNG => BCRYPT_RNG_ALGORITHM,
            RandomAlgorithmId::DUALECRNG => BCRYPT_RNG_DUAL_EC_ALGORITHM,
            RandomAlgorithmId::FIPS186DSARNG => BCRYPT_RNG_FIPS186_DSA_ALGORITHM,
        }
    }
}

impl fmt::Display for RandomAlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(*self))
    }
}

impl From<RandomAlgorithmId> for RandomAlgoHandle {
    fn from(value: RandomAlgorithmId) -> RandomAlgoHandle {
        let id: &str = value.into();

        AlgoHandle::open(id)
            .map(RandomAlgoHandle)
            .expect("Couldn't open random algorithm provider")
    }
}

impl From<RandomAlgoHandle> for RandomAlgorithm {
    fn from(value: RandomAlgoHandle) -> RandomAlgorithm {
        RandomAlgorithm::Specified(value)
    }
}

impl From<RandomAlgoHandle> for AlgoHandle {
    fn from(value: RandomAlgoHandle) -> AlgoHandle {
        value.0
    }
}

impl From<RandomAlgorithmId> for RandomAlgorithmKind {
    fn from(value: RandomAlgorithmId) -> RandomAlgorithmKind {
        RandomAlgorithmKind::Specified(value)
    }
}

impl RandomAlgorithmKind {
    /// Opens a random algorithm provider capable of generating random numbers.
    pub fn open(self) -> RandomAlgorithm {
        match self {
            Self::SystemPreferred => RandomAlgorithm::SystemPreferred,
            Self::Specified(kind) => RandomAlgorithm::Specified(kind.into()),
        }
    }
}

impl RandomAlgorithmId {
    /// Opens a random algorithm provider capable of generating random numbers.
    pub fn open(self) -> RandomAlgorithm {
        RandomAlgorithmKind::from(self).open()
    }
}

impl RandomAlgorithm {
    /// Fills a buffer with random bytes.
    pub fn gen_random(&self, buffer: &mut [u8]) -> crate::Result<()> {
        Self::gen_random_with_opts(self, buffer, RandomOptions::default())
    }

    /// Fills a buffer with random bytes. Specify `opts` for additional options.
    pub fn gen_random_with_opts(
        &self,
        buffer: &mut [u8],
        opts: RandomOptions,
    ) -> crate::Result<()> {
        let (handle, opts) = match self {
            Self::SystemPreferred => (ptr::null_mut(), opts.use_system_preferred_rng(true)),
            Self::Specified(RandomAlgoHandle(handle)) => (handle.as_ptr(), opts),
        };

        Error::check(unsafe {
            BCryptGenRandom(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as ULONG,
                opts.as_bitflags(),
            )
        })
    }
}

/// Additional options to be used when generating random numbers.
#[derive(Clone, Copy, Debug, Default)]
pub struct RandomOptions(ULONG);

impl RandomOptions {
    /// By setting this flag, the number in the output buffer will be used as
    /// additional entropy for the random number. If this flag is not specified,
    /// this function will use a random number for the entropy.
    //
    // *Windows 8 and later*:  This flag is ignored in Windows 8 and later.
    #[must_use]
    pub fn use_entropy_in_buffer(self, value: bool) -> Self {
        self.set_flag(BCRYPT_RNG_USE_ENTROPY_IN_BUFFER, value)
    }

    /// Sets `BCRYPT_USE_SYSTEM_PREFERRED_RNG`. Not meant to be used publicly.
    /// To use system-preferred RNG, please use the provider by constructing the
    /// `RandomAlgorithm::SystemPreferred` variant.
    #[must_use]
    fn use_system_preferred_rng(self, value: bool) -> Self {
        self.set_flag(BCRYPT_USE_SYSTEM_PREFERRED_RNG, value)
    }

    /// (Un)sets a provided `flag` set depending on `value`.
    #[must_use]
    fn set_flag(mut self, flag: ULONG, value: bool) -> Self {
        let value = if value { flag } else { 0 };

        self.0 = self.0 & !flag | value;
        self
    }

    /// Returns the inner bitflags to be used when calling `BCryptGenRandom`.
    fn as_bitflags(self) -> ULONG {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        let opts = RandomOptions::default();
        assert_eq!(opts.as_bitflags(), 0);

        for set_flag in &[
            RandomOptions::use_entropy_in_buffer,
            RandomOptions::use_system_preferred_rng,
        ] {
            assert_eq!(set_flag(set_flag(opts, true), false).as_bitflags(), 0);
        }

        assert_eq!(
            opts.use_entropy_in_buffer(true).as_bitflags(),
            BCRYPT_RNG_USE_ENTROPY_IN_BUFFER
        );
        assert_eq!(
            opts.use_system_preferred_rng(true).as_bitflags(),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        assert_eq!(
            opts.use_entropy_in_buffer(true)
                .use_system_preferred_rng(true)
                .as_bitflags(),
            BCRYPT_RNG_USE_ENTROPY_IN_BUFFER | BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
    }

    fn simple_test_rng(provider: RandomAlgorithm, opts: RandomOptions) {
        let empty = vec![0; 32];

        let mut buf = empty.clone();
        provider
            .gen_random_with_opts(&mut buf, opts)
            .expect("RNG to succeeed");
        assert_ne!(&buf, &empty);

        let mut buf2 = buf.clone();
        provider
            .gen_random_with_opts(&mut buf2, opts)
            .expect("RNG to succeeed");
        assert_ne!(&buf2, &empty);
        assert_ne!(&buf2, &buf);
    }

    #[test]
    fn system_preferred() {
        let provider = RandomAlgorithmKind::SystemPreferred.open();
        simple_test_rng(provider, RandomOptions::default());
    }

    #[test]
    fn rng() {
        let provider = RandomAlgorithmId::RNG.open();
        simple_test_rng(provider, RandomOptions::default());
    }

    #[test]
    fn dualecrng() {
        let provider = RandomAlgorithmId::DUALECRNG.open();
        simple_test_rng(provider, RandomOptions::default());
    }

    #[test]
    fn fips186dsarng() {
        let provider = RandomAlgorithmId::FIPS186DSARNG.open();
        simple_test_rng(provider, RandomOptions::default());
    }

    #[test]
    fn with_opts() {
        let provider = RandomAlgorithmKind::SystemPreferred.open();
        simple_test_rng(
            provider,
            RandomOptions::default().use_entropy_in_buffer(true),
        );
        let provider = RandomAlgorithmId::RNG.open();
        simple_test_rng(
            provider,
            RandomOptions::default().use_entropy_in_buffer(true),
        );
        let provider = RandomAlgorithmId::DUALECRNG.open();
        simple_test_rng(
            provider,
            RandomOptions::default().use_entropy_in_buffer(true),
        );
        let provider = RandomAlgorithmId::FIPS186DSARNG.open();
        simple_test_rng(
            provider,
            RandomOptions::default().use_entropy_in_buffer(true),
        );
    }
}
