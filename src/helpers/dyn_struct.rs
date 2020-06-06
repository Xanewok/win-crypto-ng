use super::AsBytes;

use winapi::shared::bcrypt::*;

/// C-compatible dynamic inline structure.
///
/// Can be used to house data with a header structure of a statically known size
/// but with trailing data of size dependent on the header field values.
#[repr(C)]
// #[derive(Debug)]
pub struct DynStruct<'a, T: DynStructParts<'a>>(pub(crate) T::Header, [u8]);

/// Couples both `Header` and `Tail` types used in a `DynStruct`.
pub trait DynStructParts<'a> {
    type Header;
    // type TailView: DynTailView<'a, Header = Self::Header>
    // type Tail: 'a;
    type Tail;
    fn view(header: &'a Self::Header, tail: &'a [u8]) -> Self::Tail;
    // type Tail: DynTailView<'a, Header = <Self as DynStructParts<'a>>::Header> + AsBytes<'a> + ?Sized;
}

// /// Given the aux. header data, reinterprets the tail bytes of a dynamic
// /// structure to a concrete structure.
// pub trait DynTailView<'a> {
//     type Header: ?Sized;
//     type Output;
//     fn view(header: &'a Self::Header, tail: &'a [u8]) -> Self::Tail;
// }

impl<'a, T: DynStructParts<'a>> DynStruct<'a, T> {
    pub fn header(&self) -> &T::Header {
        &self.0
    }

    pub fn view(&'a self) -> T::Tail {
        T::view(&self.0, &self.1)
    }

    pub fn as_parts(&'a self) -> (&'a T::Header, T::Tail) {
        let header = self.header();
        let view = self.view();
        (header, view)
    }

    pub fn as_bytes(&self) -> &[u8] {
        AsBytes::as_bytes(self)
    }
}

impl<'a, T: DynStructParts<'a>> AsBytes<'a> for DynStruct<'a, T> {
    fn as_bytes(&self) -> &[u8] {
        let len = std::mem::size_of_val(self);
        // SAFETY: DynStruct is C-compatible - header is assumed to be a
        // POD that's #[repr(C)] and the tail implements AsBytes.
        // Therefore, it's safe to view the entire allocation as bytes
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8 , len)
        }
    }
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
#[macro_export]
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
        $(#[$wrapper_meta])*
        pub enum $wrapper_ident {}

        $(#[$outer])*
        pub struct $tail_ident<'a> {
            $(
                $(#[$meta])*
                pub $field: &'a [u8],
            )*
        }

        $(#[$ident_meta])*
        #[repr(transparent)]
        pub struct $ident([u8]);
        impl $crate::helpers::bytes::AsBytes<'_> for $ident {
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl<'a> $crate::helpers::dyn_struct::DynStructParts<'a> for $wrapper_ident {
            type Header = $header;
            type Tail = $tail_ident<'a>;

            #[allow(unused_assignments)]
            fn view(header: &'a Self::Header, tail: &'a [u8]) -> $tail_ident<'a> {
                // let bytes = $crate::helpers::bytes::AsBytes::as_bytes(self);
                let bytes = tail;
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

        // impl<'a> $crate::helpers::dyn_struct::DynTailView<'a> for $ident {
        //     type Header = $header;
        //     type Output = $tail_ident<'a>;

        //     #[allow(unused_assignments)]
        //     fn view(&'a self, header: &'a Self::Header) -> $tail_ident<'a> {
        //         let bytes = $crate::helpers::bytes::AsBytes::as_bytes(self);
        //         let mut offset = 0;
        //         $(
        //             let field_len = dyn_struct! { header, $($len)*};
        //             let $field: &'a [u8] = &bytes[offset..offset + field_len];
        //             offset += field_len;
        //         )*

        //         $tail_ident {
        //             $($field,)*
        //         }
        //     }
        // }

        impl $crate::helpers::dyn_struct::DynStruct<'_, $wrapper_ident> {
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

                Self::from_boxed(boxed)
            }
        }

        // NOTE: This implementation can't be generic for DynStruct
        // because the T::Tail isn't known to be vtable-compatible
        // with slice types (here we have newtypes around [u8])
        impl $crate::helpers::dyn_struct::DynStruct<'_, $wrapper_ident> {
            pub fn from_boxed(boxed: Box<[u8]>) -> Box<Self> {
                dbg!(&boxed);
                let hehe: &BCRYPT_ECCKEY_BLOB = unsafe { std::mem::transmute(boxed.as_ref().as_ptr())};
                dbg!(hehe.dwMagic);
                dbg!(hehe.cbKey);
                eprintln!("Boxed len is {}", boxed.len());
                eprintln!("Align of header {} is: {}", stringify!($header), std::mem::align_of::<$header>());
                
                // TODO: Calculate padding for every field
                // Every field is padded except for the last one?
                // assert_eq!(boxed.len() % std::mem::align_of::<$header>(), 0);
                assert!(boxed.len() >= std::mem::size_of::<$header>());

                let tail_len = boxed.len() - std::mem::size_of::<$header>();
                // Construct a custom slice-based DST
                let ptr = Box::leak(boxed);
                unsafe {
                    let slice = std::slice::from_raw_parts_mut(ptr.as_mut_ptr(), tail_len);

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
