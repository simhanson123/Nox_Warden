//! Serde normally maps NaN/Infinity to JSON null. Reject all floats before that
//! lossy conversion so generic canonicalization cannot silently change meaning.
use serde::ser::{self, Serialize};

pub(crate) struct FloatGuard(pub(crate) usize);
impl FloatGuard {
    fn container(self) -> Result<Self> {
        if self.0 >= crate::MAX_DEPTH {
            return Err(ser::Error::custom("MAX_DEPTH_EXCEEDED"));
        }
        Ok(self)
    }
}
type Error = serde_json::Error;
type Result<T> = std::result::Result<T, Error>;

macro_rules! scalar {
    ($($method:ident : $ty:ty),* $(,)?) => {$ (
        fn $method(self, _: $ty) -> Result<()> { Ok(()) }
    )*};
}

impl ser::Serializer for FloatGuard {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;
    scalar!(serialize_bool:bool,serialize_i8:i8,serialize_i16:i16,serialize_i32:i32,
        serialize_i64:i64,serialize_i128:i128,serialize_u8:u8,serialize_u16:u16,
        serialize_u32:u32,serialize_u64:u64,serialize_u128:u128,serialize_char:char,
        serialize_str:&str,serialize_bytes:&[u8]);
    fn serialize_f32(self, _: f32) -> Result<()> {
        Err(ser::Error::custom("FLOAT_NOT_ALLOWED"))
    }
    fn serialize_f64(self, _: f64) -> Result<()> {
        Err(ser::Error::custom("FLOAT_NOT_ALLOWED"))
    }
    fn serialize_none(self) -> Result<()> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<()> {
        v.serialize(self)
    }
    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _: &'static str, v: &T) -> Result<()> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        v: &T,
    ) -> Result<()> {
        v.serialize(self)
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self> {
        self.container()
    }
    fn serialize_tuple(self, _: usize) -> Result<Self> {
        self.container()
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self> {
        self.container()
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self> {
        self.container()
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self> {
        self.container()
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self> {
        self.container()
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self> {
        self.container()
    }
}

macro_rules! sequence {
    ($trait:ident,$method:ident) => {
        impl ser::$trait for FloatGuard {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<()> {
                v.serialize(FloatGuard(self.0 + 1))
            }
            fn end(self) -> Result<()> {
                Ok(())
            }
        }
    };
}
sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);

impl ser::SerializeMap for FloatGuard {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<()> {
        v.serialize(FloatGuard(self.0 + 1))
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<()> {
        v.serialize(FloatGuard(self.0 + 1))
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}
impl ser::SerializeStruct for FloatGuard {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &'static str, v: &T) -> Result<()> {
        v.serialize(FloatGuard(self.0 + 1))
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}
impl ser::SerializeStructVariant for FloatGuard {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, _: &'static str, v: &T) -> Result<()> {
        v.serialize(FloatGuard(self.0 + 1))
    }
    fn end(self) -> Result<()> {
        Ok(())
    }
}
