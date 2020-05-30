//! Cryptographic key handle

use crate::dyn_struct;
use crate::helpers::{Handle, TypedBlob};
use std::ptr::null_mut;
use std::convert::TryFrom;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

/// Cryptographic key handle used in (a)symmetric algorithms
pub struct KeyHandle {
    pub(crate) handle: BCRYPT_KEY_HANDLE,
}

impl KeyHandle {
    pub fn new() -> Self {
        Self { handle: null_mut() }
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                BCryptDestroyKey(self.handle);
            }
        }
    }
}

impl Default for KeyHandle {
    fn default() -> Self {
        KeyHandle::new()
    }
}

impl Handle for KeyHandle {
    fn as_ptr(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }

    fn as_mut_ptr(&mut self) -> *mut BCRYPT_KEY_HANDLE {
        &mut self.handle
    }
}

/// Type of a key blob.
pub enum BlobType {
    AesWrapKey,
    DhPrivate,
    DhPublic,
    DsaPublic,
    DsaPrivate,
    EccPrivate,
    EccPublic,
    KeyData,
    OpaqueKey,
    PublicKey,
    PrivateKey,
    RsaFullPrivate,
    RsaPrivate,
    RsaPublic,
    LegacyDhPrivate,
    LegacyDhPublic,
    LegacyDsaPrivate,
    LegacyDsaPublic,
    LegacyDsaV2Private,
    LegacyRsaPrivate,
    LegacyRsaPublic,
}

impl BlobType {
    pub fn as_value(&self) -> &'static str {
        match self {
            BlobType::AesWrapKey => BCRYPT_AES_WRAP_KEY_BLOB,
            BlobType::DhPrivate => BCRYPT_DH_PRIVATE_BLOB,
            BlobType::DhPublic => BCRYPT_DH_PUBLIC_BLOB,
            BlobType::DsaPublic => BCRYPT_DSA_PUBLIC_BLOB,
            BlobType::DsaPrivate => BCRYPT_DSA_PRIVATE_BLOB,
            BlobType::EccPrivate => BCRYPT_ECCPRIVATE_BLOB,
            BlobType::EccPublic => BCRYPT_ECCPUBLIC_BLOB,
            BlobType::KeyData => BCRYPT_KEY_DATA_BLOB,
            BlobType::OpaqueKey => BCRYPT_OPAQUE_KEY_BLOB,
            BlobType::PublicKey => BCRYPT_PUBLIC_KEY_BLOB,
            BlobType::PrivateKey => BCRYPT_PRIVATE_KEY_BLOB,
            BlobType::RsaFullPrivate => BCRYPT_RSAFULLPRIVATE_BLOB,
            BlobType::RsaPrivate => BCRYPT_RSAPRIVATE_BLOB,
            BlobType::RsaPublic => BCRYPT_RSAPUBLIC_BLOB,
            BlobType::LegacyDhPrivate => LEGACY_DH_PRIVATE_BLOB,
            BlobType::LegacyDhPublic => LEGACY_DH_PUBLIC_BLOB,
            BlobType::LegacyDsaPrivate => LEGACY_DSA_PRIVATE_BLOB,
            BlobType::LegacyDsaPublic => LEGACY_DSA_PUBLIC_BLOB,
            BlobType::LegacyDsaV2Private => LEGACY_DSA_V2_PRIVATE_BLOB,
            BlobType::LegacyRsaPrivate => LEGACY_RSAPRIVATE_BLOB,
            BlobType::LegacyRsaPublic => LEGACY_RSAPUBLIC_BLOB,
        }
    }
}

impl<'a> TryFrom<&'a str> for BlobType {
    type Error = &'a str;

    fn try_from(val: &'a str) -> std::result::Result<BlobType, Self::Error> {
        match val {
            BCRYPT_AES_WRAP_KEY_BLOB => Ok(BlobType::AesWrapKey),
            BCRYPT_DH_PRIVATE_BLOB => Ok(BlobType::DhPrivate),
            BCRYPT_DH_PUBLIC_BLOB => Ok(BlobType::DhPublic),
            BCRYPT_DSA_PUBLIC_BLOB => Ok(BlobType::DsaPublic),
            BCRYPT_DSA_PRIVATE_BLOB => Ok(BlobType::DsaPrivate),
            BCRYPT_ECCPRIVATE_BLOB => Ok(BlobType::EccPrivate),
            BCRYPT_ECCPUBLIC_BLOB => Ok(BlobType::EccPublic),
            BCRYPT_KEY_DATA_BLOB => Ok(BlobType::KeyData),
            BCRYPT_OPAQUE_KEY_BLOB => Ok(BlobType::OpaqueKey),
            BCRYPT_PUBLIC_KEY_BLOB => Ok(BlobType::PublicKey),
            BCRYPT_PRIVATE_KEY_BLOB => Ok(BlobType::PrivateKey),
            BCRYPT_RSAFULLPRIVATE_BLOB => Ok(BlobType::RsaFullPrivate),
            BCRYPT_RSAPRIVATE_BLOB => Ok(BlobType::RsaPrivate),
            BCRYPT_RSAPUBLIC_BLOB => Ok(BlobType::RsaPublic),
            LEGACY_DH_PRIVATE_BLOB => Ok(BlobType::LegacyDhPrivate),
            LEGACY_DH_PUBLIC_BLOB => Ok(BlobType::LegacyDhPublic),
            LEGACY_DSA_PRIVATE_BLOB => Ok(BlobType::LegacyDsaPrivate),
            LEGACY_DSA_PUBLIC_BLOB => Ok(BlobType::LegacyDsaPublic),
            LEGACY_DSA_V2_PRIVATE_BLOB => Ok(BlobType::LegacyDsaV2Private),
            LEGACY_RSAPRIVATE_BLOB => Ok(BlobType::LegacyRsaPrivate),
            LEGACY_RSAPUBLIC_BLOB => Ok(BlobType::LegacyRsaPublic),
            val => Err(val),
        }
    }
}

/// Marker trait for values containing CNG key blob types.
pub trait KeyBlob {
    const MAGIC: ULONG;
    const TYPE: &'static str;
    type Value;
}

macro_rules! newtype_key_blob {
    ($($name: ident, $type: expr, $magic: tt, $value: ty),*) => {
        $(
            #[repr(transparent)]
            pub struct $name($value);
            impl AsRef<$value> for $name {
                fn as_ref(&self) -> &$value {
                    &self.0
                }
            }
            impl KeyBlob for $name {
                const MAGIC: ULONG = $magic;
                const TYPE: &'static str = $type;
                type Value = $value;
            }

            impl TryFrom<TypedBlob<BCRYPT_KEY_BLOB>> for TypedBlob<$name> {
                type Error = TypedBlob<BCRYPT_KEY_BLOB>;
                fn try_from(value: TypedBlob<BCRYPT_KEY_BLOB>) -> Result<Self, Self::Error> {
                    if value.Magic == <$name as KeyBlob>::MAGIC {
                        // SAFETY: Every specialized key blob struct extends the
                        // basic "type-erased" BCRYPT_KEY_BLOB - the magic value
                        // is a discriminant. We trust the documentation on how
                        // can we reinterpret the blob layout according to its
                        // magic.
                        Ok(unsafe { TypedBlob::from_box(value.into_inner()) })
                    } else {
                        Err(value)
                    }
                }
            }
        )*

        impl TypedBlob<BCRYPT_KEY_BLOB> {
            pub fn to_type(&self) -> Option<BlobType> {
                match self.Magic {
                    $($magic => {TryFrom::try_from($type).ok()})*
                    _ => None,
                }
            }
        }

        impl<T: KeyBlob> From<TypedBlob<T>> for TypedBlob<BCRYPT_KEY_BLOB> {
            fn from(typed: TypedBlob<T>) -> Self {
                // SAFETY: Every specialized key blob struct extends the
                // basic "type-erased" BCRYPT_KEY_BLOB, so it's safe to
                // just discard the concrete type
                unsafe { TypedBlob::from_box(typed.into_inner()) }
            }
        }
    };
}

newtype_key_blob!(
    DhPrivate,  BCRYPT_DH_PRIVATE_BLOB, BCRYPT_DH_PRIVATE_MAGIC, BCRYPT_DH_KEY_BLOB,
    DhPublic, BCRYPT_DH_PUBLIC_BLOB, BCRYPT_DH_PUBLIC_MAGIC, BCRYPT_DH_KEY_BLOB,
    DsaPublic, BCRYPT_DSA_PUBLIC_BLOB, BCRYPT_DSA_PUBLIC_MAGIC, BCRYPT_DSA_KEY_BLOB,
    DsaPrivate, BCRYPT_DSA_PRIVATE_BLOB, BCRYPT_DSA_PRIVATE_MAGIC, BCRYPT_DSA_KEY_BLOB,
    DsaPublicV2, BCRYPT_DSA_PUBLIC_BLOB, BCRYPT_DSA_PUBLIC_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2,
    DsaPrivateV2, BCRYPT_DSA_PRIVATE_BLOB, BCRYPT_DSA_PRIVATE_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2,
    RsaFullPrivate, BCRYPT_RSAFULLPRIVATE_BLOB, BCRYPT_RSAFULLPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB,
    RsaPrivate, BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB,
    RsaPublic, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSAKEY_BLOB,
    EcdhPublic, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhPrivate, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP256Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP256Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDH_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP384Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP384Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP521Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdhP521Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDH_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP256Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP256Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP384Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP384Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP521Public, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
    EcdsaP521Private, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECDSA_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB
);

impl RsaKeyPublicView for TypedBlob<RsaPublic> {}
impl RsaKeyBlobPrivate for TypedBlob<RsaPrivate> {}
impl RsaKeyBlobFullPrivate for TypedBlob<RsaFullPrivate> {}
impl DsaKeyBlobPublic for TypedBlob<DsaPublic> {}
impl DsaKeyBlobPrivate for TypedBlob<DsaPrivate> {}
impl DsaKeyBlobPublicV2 for TypedBlob<DsaPublicV2> {}
impl DsaKeyBlobPrivateV2 for TypedBlob<DsaPrivateV2> {}
impl DhKeyBlobPublic for TypedBlob<DhPublic> {}
impl DhKeyBlobPrivate for TypedBlob<DhPrivate> {}
impl EccKeyBlobPublic for TypedBlob<EcdhPublic> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhPrivate> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP256Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP256Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP384Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP384Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdhP521Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdhP521Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP256Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP256Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP384Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP384Private> {}
impl EccKeyBlobPublic for TypedBlob<EcdsaP521Public> {}
impl EccKeyBlobPrivate for TypedBlob<EcdsaP521Private> {}

dyn_struct! {
    struct RsaKeyPublicBlob,
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    tail: RsaKeyPublicView {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
    }
}

dyn_struct! {
    struct RsaKeyPrivateBlob,
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    tail: RsaKeyBlobPrivate {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
    }
}

dyn_struct! {
    struct RsaKeyFullPrivateBlob,
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    tail: RsaKeyBlobFullPrivate {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
        exponent1[cbPrime1],
        exponent2[cbPrime2],
        coeff[cbPrime1],
        priv_exp[cbModulus],
    }
}

dyn_struct! {
    struct DhKeyPublicBlob,
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    tail: DhKeyBlobPublic {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    struct DhKeyPrivateBlob,
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    #[allow(non_snake_case)]
    tail: DhKeyBlobPrivate {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[cbKey],
    }
}

dyn_struct! {
    struct DsaKeyPublicBlob,
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    tail: DsaKeyBlobPublic {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    struct DsaKeyPrivateBlob,
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    tail: DsaKeyBlobPrivate {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    struct DsaKeyPublicV2Blob,
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    tail: DsaKeyBlobPublicV2 {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    struct DsaKeyPrivateV2Blob,
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    tail: DsaKeyBlobPrivateV2 {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    struct EccKeyPublicBlob,
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    tail: EccKeyBlobPublic {
        x[cbKey],
        y[cbKey],
    }
}

dyn_struct! {
    struct EccKeyPrivateBlob,
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    tail: EccKeyBlobPrivate {
        x[cbKey],
        y[cbKey],
        d[cbKey],
    }
}
