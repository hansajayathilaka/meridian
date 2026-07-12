//! Fixed-length byte-array newtypes that (de)serialize as **CBOR byte strings** (major type 2),
//! not as CBOR arrays of integers. This keeps keys/signatures compact on the wire and matches how
//! every other implementation (WASM, mobile) will encode them.
//!
//! serde only derives `Serialize`/`Deserialize` for arrays up to length 32, so anything wider
//! (64-byte signatures) needs a hand-written impl regardless; doing it here uniformly also gives us
//! the compact byte-string encoding for the 32-byte keys.

use core::fmt;

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};

/// (De)serialize a fixed `[u8; N]` as a CBOR byte string.
pub(crate) fn serialize_array<S, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(bytes)
}

pub(crate) fn deserialize_array<'de, D, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct ArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a byte string of exactly {N} bytes")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
        }

        // Some CBOR decoders hand fixed-length data through the seq path.
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; N];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(N + 1, &self));
            }
            Ok(out)
        }
    }

    deserializer.deserialize_bytes(ArrayVisitor::<N>)
}

/// Declares a `#[serde(with)]`-compatible module for a fixed byte length, plus a `Vec<[u8; N]>`
/// helper for repeated keys/signatures in a bundle.
macro_rules! byte_field {
    ($modname:ident, $len:expr) => {
        pub(crate) mod $modname {
            use serde::{Deserializer, Serializer};

            pub fn serialize<S: Serializer>(v: &[u8; $len], s: S) -> Result<S::Ok, S::Error> {
                super::serialize_array::<S, $len>(v, s)
            }
            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; $len], D::Error> {
                super::deserialize_array::<D, $len>(d)
            }
        }
    };
}

byte_field!(b32, 32);
byte_field!(b64, 64);

/// `#[serde(with = "bytes_vec")]`: a variable-length `Vec<u8>` as a single CBOR byte string
/// (not an array of integers). Used for nested frame bodies and opaque blobs.
pub(crate) mod bytes_vec {
    use core::fmt;

    use serde::de::{self, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a CBOR byte string")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(v)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// `#[serde(with = "vec_b32")]`: a list of 32-byte keys, each a CBOR byte string.
pub(crate) mod vec_b32 {
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&Wrap32(*item))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let raw: Vec<Wrap32> = serde::Deserialize::deserialize(d)?;
        Ok(raw.into_iter().map(|w| w.0).collect())
    }

    struct Wrap32([u8; 32]);
    impl serde::Serialize for Wrap32 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            super::serialize_array::<S, 32>(&self.0, s)
        }
    }
    impl<'de> serde::Deserialize<'de> for Wrap32 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Wrap32(super::deserialize_array::<D, 32>(d)?))
        }
    }
}

/// `#[serde(with = "vec_b64")]`: a list of 64-byte signatures, each a CBOR byte string.
pub(crate) mod vec_b64 {
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[[u8; 64]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for item in v {
            seq.serialize_element(&Wrap64(*item))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 64]>, D::Error> {
        let raw: Vec<Wrap64> = serde::Deserialize::deserialize(d)?;
        Ok(raw.into_iter().map(|w| w.0).collect())
    }

    struct Wrap64([u8; 64]);
    impl serde::Serialize for Wrap64 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            super::serialize_array::<S, 64>(&self.0, s)
        }
    }
    impl<'de> serde::Deserialize<'de> for Wrap64 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(Wrap64(super::deserialize_array::<D, 64>(d)?))
        }
    }
}
