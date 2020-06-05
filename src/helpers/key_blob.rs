use std::borrow::Borrow;
use winapi::shared::bcrypt::*;
use winapi::shared::ntdef::ULONG;

trait KeyBlob<'a>
where
    Self: DynStructParts<'a>,
    Self::Header: ExtendsBcryptKeyBlob,
{
    const MAGIC: ULONG;
}

unsafe trait ExtendsBcryptKeyBlob {
    fn magic(&self) -> ULONG;
}
unsafe impl ExtendsBcryptKeyBlob for BCRYPT_RSAKEY_BLOB {
    fn magic(&self) -> ULONG {
        self.Magic
    }
}

#[repr(transparent)]
struct RsaPrivateData([u8]);
impl AsRef<[u8]> for RsaPrivateData {
    fn as_ref(&self) -> &[u8] {
        self.0.borrow()
    }
}

impl<'a> DynTailView<'a> for RsaPrivateData {
    type Input = BCRYPT_RSAKEY_BLOB;
    type Output = RsaPrivateView<'a>;
    fn view(&'a self, input: &'a Self::Input) -> RsaPrivateView<'a> {
        let bytes = self.as_ref();
        RsaPrivateView {
            pub_exp: &bytes[..input.cbPublicExp as usize],
            modulus: &bytes[
                input.cbPublicExp as usize..
                input.cbPublicExp as usize + input.cbModulus as usize
            ],
        }
    }
}

#[derive(Debug)]
struct RsaPrivateView<'a> {
    pub_exp: &'a [u8],
    modulus: &'a [u8],
}

pub enum RsaPrivate {}
impl DynStructParts<'_> for RsaPrivate {
    type Header = BCRYPT_RSAKEY_BLOB;
    type Tail = RsaPrivateData;
}

impl KeyBlob<'_> for RsaPrivate {
    const MAGIC: ULONG = BCRYPT_RSAPRIVATE_MAGIC;
}

#[repr(C)]
struct KeyData<'a, K>(K::Header, K::Tail)
where
    K: KeyBlob<'a>,
    <K as DynStructParts<'a>>::Header: ExtendsBcryptKeyBlob;

trait DynStructParts<'a> {
    type Header;
    type Tail: DynTailView<'a, Input = Self::Header> + AsRef<[u8]> + ?Sized;
}

trait DynTailView<'a>: AsRef<[u8]> {
    type Input: ?Sized;
    type Output;
    fn view(&'a self, input: &'a Self::Input) -> Self::Output;
}

trait DynStruct<'a, T>
where
    T: DynStructParts<'a>,
    T::Tail: 'a,
{
    fn header(&'a self) -> &'a T::Header;
    fn tail(&'a self) -> &'a T::Tail;

    fn as_parts(&'a self) -> (&'a T::Header, <T::Tail as DynTailView<'a>>::Output) {
        let header = self.header();
        let view = self.tail().view(header);
        (header, view)
    }
}

#[repr(C)]
struct DynStructUnsized<'a, T: DynStructParts<'a>>(T::Header, T::Tail);

impl<'a, T: 'a> DynStruct<'a, T> for DynStructUnsized<'a, T>
where
    T: DynStructParts<'a>,
    T::Tail: 'a,
{
    fn header(&'a self) -> &'a T::Header {
        &self.0
    }
    fn tail(&'a self) -> &'a T::Tail {
        &self.1
    }
}

impl<'a, K: 'a> DynStruct<'a, K> for KeyData<'a, K>
where
    K: KeyBlob<'a>,
    K::Header: ExtendsBcryptKeyBlob,
{
    fn header(&'a self) -> &'a K::Header {
        &self.0
    }
    fn tail(&'a self) -> &'a K::Tail {
        &self.1
    }
}

// TODO: Impl FromBytes for DynStructUnsized where T::Header: FromBytes

impl<'a, T: DynStructParts<'a>> DynStructUnsized<'a, T> {
    fn as_parts(&'a self) -> (&'a T::Header, <T::Tail as DynTailView<'a>>::Output) {
        DynStruct::as_parts(self)
    }
}

fn test(arg: &KeyData<RsaPrivate>) {
    let blob = &arg.0;
    let data = &arg.1;
    dbg!(blob.Magic);
    dbg!(blob.BitLength);
}

fn another<'a>(arg: &'a DynStructUnsized<'a, RsaPrivate>) {
    let (header, view) = arg.as_parts();
    dbg!(header.Magic);
    dbg!(header.BitLength);
    dbg!(view);
}

#[cfg(test)]
mod tests {
    #[test]
    fn name() {
        use crate::asymmetric::{AsymmetricKey, Export, Rsa};
        let key = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();
        let blob = key.export().unwrap();
        let blob = blob.into_inner();
        super::test(unsafe { std::mem::transmute(blob.as_ref()) });
        super::another(unsafe { std::mem::transmute(blob.as_ref()) });

        // let blob = Box::leak(blob);
        // let tail_byte_count = blob.len() - std::mem::size_of::<BCRYPT_RSAKEY_BLOB>();
        // let raw = DynStructUnsized::from_raw_parts_mut(blob.as_mut_ptr().cast(), tail_byte_count);
        // let boxed = unsafe { Box::from_raw(raw) };
        // let (header, view) = boxed.as_parts();
        // dbg!(header.Magic);
        // dbg!(header.BitLength);
        // dbg!(view);

        panic!();
    }
}

// impl DynStructUnsized<'_, RsaPrivate> {
//     pub fn from_raw_parts(data: *const BCRYPT_RSAKEY_BLOB, count: usize) -> *const Self {
//         use core::{mem, slice};

//         // https://users.rust-lang.org/t/construct-fat-pointer-to-struct/29198/9
//         // Requirements of slice::from_raw_parts.
//         assert!(!data.is_null());
//         assert!(count * mem::size_of::<u8>() <= core::isize::MAX as usize);

//         let slice = unsafe { slice::from_raw_parts(data as *const (), count) };
//         slice as *const [()] as *const Self
//     }

//     pub fn from_raw_parts_mut(data: *mut BCRYPT_RSAKEY_BLOB, count: usize) -> *mut Self {
//         use core::{mem, slice};

//         // https://users.rust-lang.org/t/construct-fat-pointer-to-struct/29198/9
//         // Requirements of slice::from_raw_parts.
//         assert!(!data.is_null());
//         assert!(count * mem::size_of::<u8>() <= core::isize::MAX as usize);

//         let slice = unsafe { slice::from_raw_parts_mut(data as *mut (), count) };
//         slice as *mut [()] as *mut Self
//     }
// }