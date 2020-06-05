use super::AsBytes;

use std::borrow::Borrow;
use winapi::shared::bcrypt::*;

/// C-compatible dynamic inline structure.
///
/// Can be used to house data with a header structure of a statically known size
/// but with trailing data of size dependent on the header field values.
#[repr(C)]
pub struct DynStruct<'a, T: DynStructParts<'a>>(T::Header, T::Tail);

/// Couples both `Header` and `Tail` types used in a `DynStruct`.
pub trait DynStructParts<'a> {
    type Header;
    type Tail: DynTailView<'a, Input = Self::Header> + AsBytes<'a> + ?Sized;
}

/// Given the aux. header data, reinterprets the tail bytes of a dynamic
/// structure to a concrete structure.
pub trait DynTailView<'a>: AsBytes<'a> {
    type Input: ?Sized;
    type Output;
    fn view(&'a self, input: &'a Self::Input) -> Self::Output;
}

impl<'a, T: DynStructParts<'a>> DynStruct<'a, T> {
    pub fn as_parts(&'a self) -> (&'a T::Header, <T::Tail as DynTailView<'a>>::Output) {
        let header = &self.0;
        let view = self.1.view(header);
        (header, view)
    }
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
macro_rules! dyn_struct {
    (
        $(#[$wrapper_meta:meta])*
        enum $wrapper_ident: ident {},
        header: $header: ty,
        $(#[$ident_meta:meta])*
        payload: #[repr(transparent)] struct $ident: ident([u8]),
        $(#[$outer:meta])*
        view: struct ref $tail_ident: ident {
            $(
                $(#[$meta:meta])*
                $field: ident [$($len: tt)*],
            )*
        }
    ) => {
        $(#[$wrapper_meta:meta])*
        pub enum $wrapper_ident {}

        $(#[$outer])*
        pub struct $tail_ident<'a> {
            $(
                $(#[$meta])*
                pub $field: &'a [u8],
            )*
        }

        $(#[$ident_meta:meta])*
        #[repr(transparent)]
        pub struct $ident([u8]);
        impl $crate::helpers::bytes::AsBytes<'_> for $ident {
            fn as_bytes(&self) -> &[u8] {
                self.0.borrow()
            }
        }

        impl<'a> $crate::helpers::key_blob::DynStructParts<'a> for $wrapper_ident {
            type Header = $header;
            type Tail = $ident;
        }

        impl<'a> $crate::helpers::key_blob::DynTailView<'a> for $ident {
            type Input = $header;
            type Output = $tail_ident<'a>;

            #[allow(unused_assignments)]
            fn view(&'a self, header: &'a Self::Input) -> $tail_ident<'a> {
                let bytes = self.as_bytes();
                let mut offset = 0;
                $(
                    let field_len = dyn_struct! { header, $($len)*};
                    let $field: &'a [u8] = &bytes[offset..offset + field_len];
                    offset += field_len;
                )*

                $tail_ident {
                    $($field,)*
                }
            }
        }

        impl $crate::helpers::key_blob::DynStruct<'_, $wrapper_ident> {
            #[allow(unused_assignments)]
            pub fn clone_from_parts(header: &$header, tail: &$tail_ident) -> Box<Self> {
                let header_len = std::mem::size_of_val(header);
                let tail_len: usize = 0 $( + dyn_struct! { header, $($len)*} )*;

                // We assume that header is #[repr(C)] and that its alignment is
                // the largest required alignment for its field.
                // We need to pad the tail allocation
                let align = std::mem::align_of_val(header);
                let tail_padding = (align - (tail_len % align)) % align;

                dbg!(header_len);
                dbg!(tail_len);
                dbg!(tail_padding);

                let mut boxed = vec![0u8; header_len + tail_len + tail_padding].into_boxed_slice();
                dbg!(boxed.len());

                let header_as_bytes = unsafe {
                    std::slice::from_raw_parts(
                        header as *const _ as *const u8,
                        header_len
                    )
                };
                &mut boxed[..header_len].copy_from_slice(header_as_bytes);
                let mut offset = header_len;
                $(
                    let field_len = dyn_struct! { header, $($len)*};
                    dbg!(tail.$field, field_len);
                    &mut boxed[offset..offset + field_len].copy_from_slice(tail.$field);
                    offset += field_len;
                )*

                // Construct a custom slice-based DST
                let ptr = Box::leak(boxed);
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr.as_mut_ptr(), tail_len);

                    // NOTE: This implementation can't be generic for DynStruct
                    // because the T::Tail isn't known to be vtable-compatible
                    // with slice types (here we have newtypes around [u8])
                    Box::from_raw(slice as *mut [u8] as *mut [()] as *mut Self)
                }
            }
        }
    };

    // Accept either header member values or arbitrary expressions (e.g. numeric
    // constants)
    ($this: expr, $ident: ident) => { $this.$ident as usize };
    ($this: expr, $expr: expr) => { $expr };

}

dyn_struct! {
    enum RsaPublic {},
    header: BCRYPT_RSAKEY_BLOB,
    payload: #[repr(transparent)] struct RsaPublicData([u8]),
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[derive(Debug)]
    view: struct ref RsaPublicTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
    }
}

dyn_struct! {
    enum RsaPrivate {},
    header: BCRYPT_RSAKEY_BLOB,
    payload: #[repr(transparent)] struct RsaPrivateData([u8]),
    /// All the fields are stored as a big-endian multiprecision integer.
    /// See https://docs.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob.
    #[derive(Debug)]
    view: struct ref RsaPrivateTail {
        pub_exp[cbPublicExp],
        modulus[cbModulus],
        prime1[cbPrime1],
        prime2[cbPrime2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        #[repr(C)]
        pub struct Header { count: u16 }
        dyn_struct! {
        enum MyDynStruct {},
            header: Header,
            payload: #[repr(transparent)] struct TailData([u8]),
            view: struct ref TailView {
                some_member[count], // Refers to run-time value of `count` field
            }
        }

        let inline = DynStruct::<MyDynStruct>::clone_from_parts(
            &Header { count: 4 },
            &TailView { some_member: &[1u8, 2, 3, 4] }
        );
        assert_eq!(6, std::mem::size_of_val(&*inline));

        let inline = DynStruct::<MyDynStruct>::clone_from_parts(
            &Header { count: 5 },
            &TailView { some_member: &[1u8, 2, 3, 4, 5] }
        );
        // Account for trailing padding
        assert_eq!(8, std::mem::size_of_val(&*inline));

    }
}
