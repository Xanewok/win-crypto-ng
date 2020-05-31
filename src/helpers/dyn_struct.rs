use std::marker::PhantomData;

use super::AsBytes;

pub struct DynStructBox<'a, H: 'a, T: DynTail<'a, H>>(Box<[u8]>, PhantomData<&'a H>, PhantomData<T>);
impl<'a, T, H: DynTail<'a, T>> AsBytes<'a> for DynStructBox<'a, T, H> {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

unsafe impl<'a, H, T> DynStruct<'a, H, T> for DynStructBox<'a, H, T>
    where
    H: 'a,
    T: DynTail<'a, H> {}

impl<'a, T, H: DynTail<'a, T>> DynStructBox<'a, T, H> {
    #[allow(dead_code)]
    pub unsafe fn from_box(allocation: Box<[u8]>) -> Self {
        Self(allocation, PhantomData, PhantomData)
    }
}

pub unsafe trait DynStruct<'a, H: 'a, T: DynTail<'a, H>>: AsBytes<'a> {
    fn header(&'a self) -> &'a H {
        let storage = &self.as_bytes()[..std::mem::size_of::<H>()];
        unsafe { &*storage.as_ptr().cast() }
    }
    fn tail(&'a self) -> T {
        let tail = &self.as_bytes()[std::mem::size_of::<H>()..];
        let header: &'a H = self.header();
        DynTail::from_bytes(header, tail)
    }
}

pub unsafe trait DynTail<'a, H> {
    fn from_bytes(header: &'a H, bytes: &'a [u8]) -> Self;
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
#[macro_export]
macro_rules! dyn_struct {
    (
        struct $wrapper_ident: ident,
        header: $header: ty,
        $(#[$outer:meta])*
        tail: trait $ident: ident; struct $tail_ident: ident {
            $(
                $(#[$meta:meta])*
                $field: ident [$($len: tt)*],
            )*
        }
    ) => {
        $(#[$outer])*
        pub trait $ident<'a>: $crate::helpers::AsBytes<'a> + AsRef<$header> {
            dyn_struct! { ;
                $(
                    $(#[$meta])*
                    $field [$($len)*],
                )*
            }
        }

        #[derive(Debug)]
        pub struct $tail_ident<'a> {
            $(
                $(#[$meta])*
                pub $field: &'a [u8],
            )*
        }

        #[repr(transparent)]
        pub struct $wrapper_ident($header);
        impl AsRef<$header> for $wrapper_ident {
            fn as_ref(&self) -> &$header {
                &self.0
            }
        }

        unsafe impl<'a> $crate::helpers::dyn_struct::DynTail<'a, $header> for $tail_ident<'a> {
            #[allow(unused_assignments)]
            fn from_bytes<'b>(header: &'b $header, bytes: &'a [u8]) -> $tail_ident<'a> {
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

        impl $crate::helpers::TypedBlob<$wrapper_ident> {
            #[allow(unused_assignments)]
            pub fn from_parts(header: &$header, tail: &$tail_ident) -> Self {
                let header_len = std::mem::size_of_val(header);
                let total_size: usize = header_len
                $(
                    + dyn_struct! { header, $($len)*}
                )*;

                let mut boxed = vec![0u8; total_size].into_boxed_slice();
                let header_as_bytes = unsafe { std::slice::from_raw_parts(
                    header as *const _ as *const u8,
                    header_len
                ) };
                &mut boxed[..header_len].copy_from_slice(header_as_bytes);
                let mut offset = header_len;
                $(
                    let field_len = dyn_struct! { header, $($len)*};
                    &mut boxed[offset..offset + field_len].copy_from_slice(tail.$field);
                    offset += field_len;
                )*
                unsafe { $crate::helpers::TypedBlob::from_box(boxed) }
            }
        }
    };
    // Expand fields. Recursively expand each field, pushing the processed field
    //  identifier to a queue which is later used to calculate field offset for
    // subsequent fields
    (
        $($prev: ident,)* ;
        $(#[$curr_meta:meta])*
        $curr: ident [$($curr_len: tt)*],
        $(
            $(#[$field_meta:meta])*
            $field: ident [$($field_len: tt)*],
        )*
    ) => {
        $(#[$curr_meta])*
        #[inline(always)]
        fn $curr(&'a self) -> &'a [u8] {
            let this = self.as_ref();

            let offset = std::mem::size_of_val(this)
                $(+ self.$prev().len())*;

            let size: usize = dyn_struct! { this, $($curr_len)* };

            &self.as_bytes()[offset..offset + size]
        }
        // Once expanded, push the processed ident and recursively expand other
        // fields
        dyn_struct! { $($prev,)* $curr, ;
            $(
                $(#[$field_meta])*
                $field [$($field_len)*],
            )*
        }
    };

    ($($prev: ident,)* ; ) => {};
    // Accept either header member values or arbitrary expressions (e.g. numeric
    // constants)
    ($this: expr, $ident: ident) => { $this.$ident as usize };
    ($this: expr, $expr: expr) => { $expr };

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::TypedBlob;

    #[test]
    fn dyn_struct() {
        #[repr(C)]
        #[derive(Debug, PartialEq)]
        pub struct MyHeader {
            count: u8,
            some: u16,
            another: u8,
        }; // 6 bytes
        #[derive(Debug)]
        #[repr(C)]
        struct MyDynStruct([u8; 12]);
        dyn_struct! {
            struct MyDynStructBlob,
            header: MyHeader,
            tail: trait MyDynStructView; struct MyDynStructTail {
                field1[count],
                field2[4],
            }
        };

        impl AsRef<MyHeader> for MyDynStruct {
            fn as_ref(&self) -> &MyHeader {
                let storage = &self.0[..std::mem::size_of::<MyHeader>()];
                unsafe { &*storage.as_ptr().cast() }
            }
        }
        impl AsBytes<'_> for MyDynStruct {
            fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }
        impl MyDynStructView<'_> for MyDynStruct {}

        let header = MyHeader {
            count: 0x02,
            some: 0xFFFF,
            another: 0x03,
        };
        let dyn_struct = MyDynStruct([
            0x2,  // MyHeader.count
            0x00, // MyHeader.some (padding)
            0xFF, 0xFF, // MyHeader.some
            0x03, // MyHeader.another
            0x00, // header padding to largest member alignment (MyHeader.some)
            0xDD, 0xDD, // field1[count]
            0xA, 0xB, 0xC, 0xD, // field2[4]
            ]);
            dbg!(std::mem::size_of::<MyHeader>());
            assert_eq!(dyn_struct.header(), &header);
            assert_eq!(dyn_struct.tail().field1, &[0xDD, 0xDD]);
            assert_eq!(dyn_struct.tail().field2, &[0xA, 0xB, 0xC, 0xD]);

        unsafe impl<'a> DynStruct<'a, MyHeader, MyDynStructTail<'a>> for MyDynStruct {}
        dbg!(dyn_struct.header());
        assert_eq!(dyn_struct.header(), dyn_struct.as_ref());
        assert_eq!(dyn_struct.tail().field1, dyn_struct.field1());
        assert_eq!(dyn_struct.tail().field2, dyn_struct.field2());

        let raw = TypedBlob::<MyDynStructBlob>::from_parts(
            &header,
            &MyDynStructTail {
                field1: &[0xDD, 0xDD],
                field2: &[0xA, 0xB, 0xC, 0xD]
            }
        );
        // NOTE: The padding bytes' value is not defined and may change
        assert_eq!(dyn_struct.0, raw.as_bytes());

        let blob = unsafe { TypedBlob::<MyHeader>::from_box(Box::new(dyn_struct.0)) };
        impl MyDynStructView<'_> for TypedBlob<MyHeader> {}
        unsafe impl<'a> DynStruct<'a, MyHeader, MyDynStructTail<'a>> for TypedBlob<MyHeader> {}
        impl AsRef<MyHeader> for MyHeader {
            fn as_ref(&self) -> &MyHeader {
                self
            }
        }
        assert_eq!(blob.as_ref(), &header);
        assert_eq!(blob.tail().field1, &[0xDD, 0xDD]);
        assert_eq!(blob.tail().field2, &[0xA, 0xB, 0xC, 0xD]);
    }
}
