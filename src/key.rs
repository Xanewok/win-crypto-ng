//! Cryptographic key handle

use crate::dyn_struct;
use crate::helpers::Handle;
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

    fn try_from(val: &'a str) -> Result<BlobType, Self::Error> {
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

use crate::helpers::dyn_struct::{DynStruct, DynStructParts};

trait KeyData<'a, T>
where
    T: DynStructParts<'a>,
    T::Header: ExtendsBcryptKeyBlob,
{

}

// impl<'a, T: DynStructParts<'a>> AsRef<DynStruct<'a, ErasedKeyBlob>> for &DynStruct<'a, T> {
//     fn as_ref(&self) -> &'a DynStruct<'a, ErasedKeyBlob> {
//         let slice = *self as *const _ as *const [()];
//         // let slice = std::slice::from_raw_parts(self as *const [()] len: usize)
//         unimplemented!()
//     }
// }

impl<'a, T> KeyData<'a, T> for DynStruct<'a, T>
where
    T: DynStructParts<'a>,
    T::Header: ExtendsBcryptKeyBlob {}

unsafe trait ExtendsBcryptKeyBlob {
    fn magic(&self) -> ULONG;
}
unsafe impl ExtendsBcryptKeyBlob for BCRYPT_RSAKEY_BLOB {
    fn magic(&self) -> ULONG {
        self.Magic
    }
}

// impl<'a, T: DynStructParts<'a>> KeyData<'a, T> for RsaPrivate where
// T::Header: ExtendsBcryptKeyBlob {
//     // const MAGIC: ULONG = BCRYPT_RSAPRIVATE_MAGIC;
// }

// #[repr(C)]
// struct KeyData<'a, K>(K::Header, K::Tail)
// where
//     K: KeyBlob<'a>,
//     <K as DynStructParts<'a>>::Header: ExtendsBcryptKeyBlob;

/// Marker trait for values containing CNG key blob types.
pub trait KeyBlob: Sized {
    const VALID_MAGIC: &'static [ULONG];
    const BLOB_TYPE: BlobType;

    // Works around not being able to implement TryFrom in generic ('a) contexts
    fn from_erased<'a>(
        erased: Box<DynStruct<'a, ErasedKeyBlob>>
    ) -> std::result::Result<
            Box<DynStruct<'a, Self>>,
            Box<DynStruct<'a, ErasedKeyBlob>>
        >
        where Self: crate::helpers::dyn_struct::DynStructParts<'a>;
}

// impl<T: KeyBlob> From<TypedBlob<T>> for TypedBlob<BCRYPT_KEY_BLOB> {
//     fn from(typed: TypedBlob<T>) -> Self {
//         // SAFETY: Every specialized key blob struct extends the
//         // basic "type-erased" BCRYPT_KEY_BLOB, so it's safe to
//         // just discard the concrete type
//         unsafe { TypedBlob::from_box(typed.into_inner()) }
//     }
// }

// TODO: This is a big, big mess.
// Currently, the `newtype_key_blob` macro defines a dynamic hierarchy for key
// blob types, introducing its own transparent newtypes to be used in tandem
// with `TypedBlob`.
// However, `dyn_struct!` also does that to facilitate creating typed blobs from
// both header and tail parts (using `from_parts` function).
// Ideally we shouldn't use the typed blobs or the transparent newtypes and use
// regular Rust DSTs coupled with unsized enums and explicit discriminants but
// since Rust doesn't properly support the three combined... ¯\_(ツ)_/¯

macro_rules! newtype_key_blob {
    // ($($name: ident, $type: expr, $tt, $value: ty),*) => {
    ($($name: ident, $blob: expr, [$($val: expr),*]),*) => {
        $(
            // #[repr(transparent)]
            // pub struct $name($value);
            // impl AsRef<$value> for $name {
            //     fn as_ref(&self) -> &$value {
            //         &self.0
            //     }
            // }

            // impl KeyBlob for $name {
            //     const MAGIC: ULONG = $magic;
            //     const TYPE: &'static str = $type;
            //     type Value = $value;
            // }

            impl<'a> AsRef<DynStruct<'a, ErasedKeyBlob>> for DynStruct<'a, $name> {
                fn as_ref(&self) -> &DynStruct<'a, ErasedKeyBlob> {
                    // Adjust the length component
                    let header_len = std::mem::size_of::<<ErasedKeyBlob as DynStructParts>::Header>();
                    let tail_len = std::mem::size_of_val(self) - header_len;

                    let slice: &'a _ = unsafe {
                        std::slice::from_raw_parts(
                            self as *const _ as *const (),
                            tail_len
                        )
                    };

                    // SAFETY:
                    // 1. DST "vtable" metadata correctness is checked by the compiler
                    // 2. The lifetime of both references is the same
                    unsafe { &*(slice as *const [()] as * const DynStruct<'a, ErasedKeyBlob>) }
                }
            }

            impl KeyBlob for $name {
                const VALID_MAGIC: &'static [ULONG] = &[$($val),*];
                const BLOB_TYPE: BlobType = $blob;

                // Works around not being able to implement TryFrom in generic
                // ('a) contexts
                // NOTE: Can't be implemented as a default trait function due to
                // possible vtable mismatch (we can't guarantee T::Tail to be
                // layout compatible with [u8] via trait bounds)
                fn from_erased<'a>(
                    boxed: Box<DynStruct<'a, ErasedKeyBlob>>
                ) -> std::result::Result<
                        Box<DynStruct<'a, Self>>,
                        Box<DynStruct<'a, ErasedKeyBlob>>
                    >
                    where Self: crate::helpers::dyn_struct::DynStructParts<'a>,
                {
                    let accepts_all = Self::VALID_MAGIC == &[];
                    if accepts_all || Self::VALID_MAGIC.iter().any(|&x| x == boxed.magic()) {
                        // Adjust the length component
                        let header_len = std::mem::size_of::<<Self as DynStructParts>::Header>();
                        let len = std::mem::size_of_val(boxed.as_ref());
                        let tail_len = len - header_len;

                        // Construct a custom slice-based DST
                        let ptr = Box::into_raw(boxed);
                        Ok(unsafe {
                            let slice = std::slice::from_raw_parts_mut(
                                ptr as *mut (),
                                tail_len
                            );

                            Box::from_raw(slice as *mut[()] as *mut DynStruct<'a, Self>)
                        })
                    } else {
                        Err(boxed)
                    }
                }
            }

            // // FFS Generic impl says fuck you
            // impl Into<Box<DynStruct<'_, ErasedKeyBlob>>> for Box<DynStruct<'_, $name>> {
            //     fn into<'a>(self) -> Box<DynStruct<'a, ErasedKeyBlob>> {
            //         let len = std::mem::size_of_val(&self);
            //         // Convert to Box<[u8]>
            //         // TODO: Abstract this
            //         let ptr = Box::into_raw(self);
            //         let boxed = unsafe {
            //             let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len);

            //             Box::from_raw(slice)
            //         };

            //         DynStruct::<'a, ErasedKeyBlob>::from_boxed(boxed)
            //     }
            // }

            // impl<'a> TryFrom<Box<DynStruct<'a, ErasedKeyBlob>>> for Box<DynStruct<'a, ErasedKeyBlob>> {
                
            // }
            // impl TryFrom<TypedBlob<BCRYPT_KEY_BLOB>> for TypedBlob<$name> {
            //     type Error = TypedBlob<BCRYPT_KEY_BLOB>;
            //     fn try_from(value: TypedBlob<BCRYPT_KEY_BLOB>) -> Result<Self, Self::Error> {
            //         if value.Magic == <$name as KeyBlob>::MAGIC {
            //             // SAFETY: Every specialized key blob struct extends the
            //             // basic "type-erased" BCRYPT_KEY_BLOB - the magic value
            //             // is a discriminant. We trust the documentation on how
            //             // can we reinterpret the blob layout according to its
            //             // magic.
            //             Ok(unsafe { TypedBlob::from_box(value.into_inner()) })
            //         } else {
            //             Err(value)
            //         }
            //     }
            // }
        )*

        // impl TypedBlob<BCRYPT_KEY_BLOB> {
        //     pub fn to_type(&self) -> Option<BlobType> {
        //         match self.Magic {
        //             $($magic => {TryFrom::try_from($type).ok()})*
        //             _ => None,
        //         }
        //     }
        // }
    };
}

newtype_key_blob! {
    ErasedKeyBlob, BlobType::RsaPublic, [],
    DhKeyPublicBlob, BlobType::DhPublic, [BCRYPT_DH_PUBLIC_MAGIC],
    DhKeyPrivateBlob, BlobType::DhPrivate, [BCRYPT_DH_PRIVATE_MAGIC],
    DsaKeyPublicBlob, BlobType::DsaPublic, [BCRYPT_DSA_PUBLIC_MAGIC],
    DsaKeyPrivateBlob, BlobType::DsaPrivate, [BCRYPT_DSA_PRIVATE_MAGIC],
    DsaKeyPublicV2Blob, BlobType::DsaPublic, [BCRYPT_DSA_PUBLIC_MAGIC_V2],
    DsaKeyPrivateV2Blob, BlobType::DsaPrivate, [BCRYPT_DSA_PRIVATE_MAGIC_V2],
    EccKeyPublicBlob, BlobType::EccPublic, [
        BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDH_PUBLIC_P256_MAGIC,
        BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECDH_PUBLIC_P521_MAGIC,
        BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
        BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PUBLIC_P521_MAGIC
    ],
    EccKeyPrivateBlob, BlobType::EccPrivate, [
        BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, BCRYPT_ECDH_PRIVATE_P256_MAGIC,
        BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECDH_PRIVATE_P521_MAGIC,
        BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC, BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
        BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECDSA_PRIVATE_P521_MAGIC
    ],
    RsaKeyPublicBlob, BlobType::RsaPublic, [BCRYPT_RSAPUBLIC_MAGIC],
    RsaKeyPrivateBlob, BlobType::RsaPrivate, [BCRYPT_RSAPRIVATE_MAGIC],
    RsaKeyFullPrivateBlob, BlobType::RsaFullPrivate, [BCRYPT_RSAFULLPRIVATE_MAGIC]
}

// newtype_key_blob!(
//     DhPrivate, BCRYPT_DH_PRIVATE_MAGIC, BCRYPT_DH_KEY_BLOB,
//     DhPublic, BCRYPT_DH_PUBLIC_MAGIC, BCRYPT_DH_KEY_BLOB,
//     DsaPublic, BCRYPT_DSA_PUBLIC_MAGIC, BCRYPT_DSA_KEY_BLOB,
//     DsaPrivate, BCRYPT_DSA_PRIVATE_MAGIC, BCRYPT_DSA_KEY_BLOB,
//     DsaPublicV2, BCRYPT_DSA_PUBLIC_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2,
//     DsaPrivateV2, BCRYPT_DSA_PRIVATE_MAGIC_V2, BCRYPT_DSA_KEY_BLOB_V2,
//     RsaFullPrivate, BCRYPT_RSAFULLPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB,
//     RsaPrivate, BCRYPT_RSAPRIVATE_MAGIC, BCRYPT_RSAKEY_BLOB,
//     RsaPublic, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_RSAKEY_BLOB,
//     EcdhPublic, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhPrivate, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP256Public, BCRYPT_ECDH_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP256Private, BCRYPT_ECDH_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP384Public, BCRYPT_ECDH_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP384Private, BCRYPT_ECDH_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP521Public, BCRYPT_ECDH_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdhP521Private, BCRYPT_ECDH_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP256Public, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP256Private, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP384Public, BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP384Private, BCRYPT_ECDSA_PRIVATE_P384_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP521Public, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_ECCKEY_BLOB,
//     EcdsaP521Private, BCRYPT_ECDSA_PRIVATE_P521_MAGIC, BCRYPT_ECCKEY_BLOB
// );

dyn_struct! {
    enum ErasedKeyBlob {},
    header: BCRYPT_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    payload: #[repr(transparent)] struct ErasedKeyBlobData([u8]),
    view: struct ref ErasedKeyBlobView {
        phantom[0],
    }
}


dyn_struct! {
    enum RsaKeyPublicBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    payload: #[repr(transparent)] struct RsaPublicData([u8]),
    view: struct ref RsaKeyPublicViewTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
    }
}

dyn_struct! {
    #[derive(Debug)]
    enum RsaKeyPrivateBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[derive(Debug)]
    payload: #[repr(transparent)] struct RsaKeyBlobPrivate([u8]),
    #[derive(Debug)]
    view: struct ref RsaKeyBlobPrivateTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
    }
}

dyn_struct! {
    enum RsaKeyFullPrivateBlob {},
    header: BCRYPT_RSAKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    payload: #[repr(transparent)] struct RsaKeyBlobFullPrivate([u8]),
    view: struct ref RsaKeyBlobFullPrivateTail {
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
    enum DhKeyPublicBlob {},
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    payload: #[repr(transparent)] struct DhKeyBlobPublic([u8]),
    view: struct ref DhKeyBlobPublicTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    enum DhKeyPrivateBlob {},
    header: BCRYPT_DH_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dh_key_blob
    payload: #[repr(transparent)] struct DhKeyBlobPrivate([u8]),
    view: struct ref DhKeyBlobPrivateTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[cbKey],
    }
}

dyn_struct! {
    enum DsaKeyPublicBlob {},
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    payload: #[repr(transparent)] struct DsaKeyBlobPublic([u8]),
    view: struct ref DsaKeyBlobPublicTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    enum DsaKeyPrivateBlob {},
    header: BCRYPT_DSA_KEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
    payload: #[repr(transparent)] struct DsaKeyBlobPrivate([u8]),
    view: struct ref DsaKeyBlobPrivateTail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    enum DsaKeyPublicV2Blob {},
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    payload: #[repr(transparent)] struct DsaKeyBlobPublicV2([u8]),
    view: struct ref DsaKeyBlobPublicV2Tail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
    }
}

dyn_struct! {
    enum DsaKeyPrivateV2Blob {},
    header: BCRYPT_DSA_KEY_BLOB_V2,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob_v2
    payload: #[repr(transparent)] struct DsaKeyBlobPrivateV2([u8]),
    view: struct ref DsaKeyBlobPrivateV2Tail {
        modulus[cbKey],
        generator[cbKey],
        public[cbKey],
        priv_exp[20],
    }
}

dyn_struct! {
    enum EccKeyPublicBlob {},
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    payload: #[repr(transparent)] struct EccKeyBlobPublic([u8]),
    view: struct ref EccKeyBlobPublicTail {
        x[cbKey],
        y[cbKey],
    }
}

dyn_struct! {
    enum EccKeyPrivateBlob {},
    header: BCRYPT_ECCKEY_BLOB,
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
    payload: #[repr(transparent)] struct EccKeyBlobPrivate([u8]),
    view: struct ref EccKeyBlobPrivateTail {
        x[cbKey],
        y[cbKey],
        d[cbKey],
    }
}

impl DynStruct<'_, ErasedKeyBlob> {
    // NOTE: This is required as trait solving can hit some limitations when
    // trying to solve `<ErasedKeyBlob as
    // helpers::dyn_struct::DynStructParts<'a>>::Header` as `BCRYPT_KEY_BLOB`,
    // so just provide the explicit method
    pub fn magic(&self) -> ULONG {
        self.header().Magic
    }

    pub fn blob_type(&self) -> Option<BlobType> {
        Some(match self.header().Magic {
            BCRYPT_DH_PRIVATE_MAGIC => BlobType::DhPrivate,
            BCRYPT_DH_PUBLIC_MAGIC => BlobType::DhPublic,
            BCRYPT_DSA_PUBLIC_MAGIC |
            BCRYPT_DSA_PUBLIC_MAGIC_V2 => BlobType::DsaPublic,
            BCRYPT_DSA_PRIVATE_MAGIC |
            BCRYPT_DSA_PRIVATE_MAGIC_V2 => BlobType::DsaPrivate,
            BCRYPT_RSAFULLPRIVATE_MAGIC => BlobType::RsaFullPrivate,
            BCRYPT_RSAPRIVATE_MAGIC => BlobType::RsaPrivate,
            BCRYPT_RSAPUBLIC_MAGIC => BlobType::RsaPublic,
            BCRYPT_ECDH_PUBLIC_P256_MAGIC |
            BCRYPT_ECDH_PUBLIC_P384_MAGIC |
            BCRYPT_ECDH_PUBLIC_P521_MAGIC |
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC |
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC |
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC |
            BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC => BlobType::EccPublic,
            BCRYPT_ECDH_PRIVATE_P256_MAGIC |
            BCRYPT_ECDH_PRIVATE_P384_MAGIC |
            BCRYPT_ECDH_PRIVATE_P521_MAGIC |
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC |
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC |
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC |
            BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC => BlobType::EccPrivate,
            _ => return None
        })
    }
}