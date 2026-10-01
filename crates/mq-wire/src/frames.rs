// spec §2.3; mirrors src/wire/mq_wire.c
//! AUTH and CONNECT_TCP control frames. All fixed ints are big-endian; a
//! `string` is a varint length + raw bytes. Decoders are strict (truncation →
//! `Short`, over-cap field / bad address type → `BadValue`), accept
//! non-minimal varints, skip trailing padding, and keep `status` /
//! `error_code` raw. Encoders never allocate and always write
//! `padding_length = 0`.
use crate::varint;

/// Buffer size hint for encoding any frame in this module.
pub const MAX_FRAME: usize = 512;
pub const STREAM_TYPE_CONNECT_TCP: u64 = 0x01;
/// SP2; constant only.
pub const STREAM_TYPE_UDP_SESSION: u64 = 0x02;
pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;

const MAX_CLIENT_ID: usize = 63;
const MAX_AUTH_TOKEN: usize = 255;
const MAX_SERVER_ID: usize = 63;
const MAX_HOST: usize = 255;
const MAX_MESSAGE: usize = 255;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthErr {
    Ok = 0,
    Failed = 1,
    TokenExpired = 2,
    PolicyDenied = 3,
}

impl AuthErr {
    pub fn from_raw(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::Failed),
            2 => Some(Self::TokenExpired),
            3 => Some(Self::PolicyDenied),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TcpErr {
    Ok = 0,
    DnsFailed = 1,
    ConnRefused = 2,
    Timeout = 3,
    PolicyDenied = 4,
}

impl TcpErr {
    pub fn from_raw(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Ok),
            1 => Some(Self::DnsFailed),
            2 => Some(Self::ConnRefused),
            3 => Some(Self::Timeout),
            4 => Some(Self::PolicyDenied),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddrType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl AddrType {
    pub fn from_raw(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Ipv4),
            0x03 => Some(Self::Domain),
            0x04 => Some(Self::Ipv6),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Short,
    BadValue,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    Short,
    TooLong,
    /// varint > 2^62-1
    BadValue,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthReq<'a> {
    pub version: u64,
    pub client_id: &'a [u8],
    pub auth_token: &'a [u8],
    pub features: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthResp<'a> {
    pub status: u8,
    pub error_code: u64,
    pub server_id: &'a [u8],
    pub features: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectTcpReq<'a> {
    pub flags: u64,
    pub address_type: AddrType,
    pub host: &'a [u8],
    pub port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectTcpResp<'a> {
    pub status: u8,
    pub error_code: u64,
    pub message: &'a [u8],
}

// spec §2.3: status/error_code are kept raw; typed accessors return None for unknown values.
impl AuthResp<'_> {
    pub fn error(&self) -> Option<AuthErr> {
        AuthErr::from_raw(self.error_code)
    }
    pub fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}

impl ConnectTcpResp<'_> {
    pub fn error(&self) -> Option<TcpErr> {
        TcpErr::from_raw(self.error_code)
    }
    pub fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}

// ---- private cursors mirroring the C put_*/get_* helpers ----

struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let rest = &self.buf[self.off..];
        if n > rest.len() {
            return Err(DecodeError::Short);
        }
        self.off += n;
        Ok(&rest[..n])
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let (v, n) = varint::decode(&self.buf[self.off..]).map_err(|_| DecodeError::Short)?;
        self.off += n;
        Ok(v)
    }
    // spec §2.3: declared length over the cap is BadValue, checked before the bytes are required.
    fn string(&mut self, cap: usize) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()?;
        if len > cap as u64 {
            return Err(DecodeError::BadValue);
        }
        self.bytes(len as usize)
    }
    /// Reads padding_length, skips that many bytes (bounds-checked), returns frame length.
    fn finish(mut self) -> Result<usize, DecodeError> {
        let pad = self.varint()?;
        let pad = usize::try_from(pad).map_err(|_| DecodeError::Short)?;
        self.bytes(pad)?;
        Ok(self.off)
    }
}

struct CursorMut<'a> {
    buf: &'a mut [u8],
    off: usize,
}

impl<'a> CursorMut<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, off: 0 }
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        let dst = self.buf[self.off..]
            .get_mut(..b.len())
            .ok_or(EncodeError::Short)?;
        dst.copy_from_slice(b);
        self.off += b.len();
        Ok(())
    }
    fn varint(&mut self, v: u64) -> Result<(), EncodeError> {
        self.off += varint::encode(&mut self.buf[self.off..], v).map_err(|e| match e {
            varint::Error::TooLarge => EncodeError::BadValue,
            varint::Error::Short => EncodeError::Short,
        })?;
        Ok(())
    }
    fn string(&mut self, s: &[u8], cap: usize) -> Result<(), EncodeError> {
        if s.len() > cap {
            return Err(EncodeError::TooLong);
        }
        self.varint(s.len() as u64)?;
        self.bytes(s)
    }
    /// Writes padding_length = 0 and returns the frame length.
    fn finish(mut self) -> Result<usize, EncodeError> {
        self.varint(0)?;
        Ok(self.off)
    }
}

// ---- AUTH_REQUEST: varint version | string client_id | string auth_token | varint features | padding ----
impl<'a> AuthReq<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = CursorMut::new(out);
        w.varint(self.version)?;
        w.string(self.client_id, MAX_CLIENT_ID)?;
        w.string(self.auth_token, MAX_AUTH_TOKEN)?;
        w.varint(self.features)?;
        w.finish()
    }

    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Cursor::new(buf);
        let f = Self {
            version: r.varint()?,
            client_id: r.string(MAX_CLIENT_ID)?,
            auth_token: r.string(MAX_AUTH_TOKEN)?,
            features: r.varint()?,
        };
        Ok((f, r.finish()?))
    }
}

// ---- AUTH_RESPONSE: u8 status | varint error_code | string server_id | varint features | padding ----
impl<'a> AuthResp<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = CursorMut::new(out);
        w.bytes(&[self.status])?;
        w.varint(self.error_code)?;
        w.string(self.server_id, MAX_SERVER_ID)?;
        w.varint(self.features)?;
        w.finish()
    }

    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Cursor::new(buf);
        let f = Self {
            status: r.u8()?,
            error_code: r.varint()?,
            server_id: r.string(MAX_SERVER_ID)?,
            features: r.varint()?,
        };
        Ok((f, r.finish()?))
    }
}

// ---- CONNECT_TCP_REQUEST: varint flags | u8 address_type | string host | u16be port | padding ----
impl<'a> ConnectTcpReq<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = CursorMut::new(out);
        w.varint(self.flags)?;
        w.bytes(&[self.address_type as u8])?;
        w.string(self.host, MAX_HOST)?;
        w.bytes(&self.port.to_be_bytes())?;
        w.finish()
    }

    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Cursor::new(buf);
        let flags = r.varint()?;
        let address_type = AddrType::from_raw(r.u8()?).ok_or(DecodeError::BadValue)?;
        let f = Self {
            flags,
            address_type,
            host: r.string(MAX_HOST)?,
            port: r.u16()?,
        };
        Ok((f, r.finish()?))
    }
}

// ---- CONNECT_TCP_RESPONSE: u8 status | varint error_code | string message | padding ----
impl<'a> ConnectTcpResp<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = CursorMut::new(out);
        w.bytes(&[self.status])?;
        w.varint(self.error_code)?;
        w.string(self.message, MAX_MESSAGE)?;
        w.finish()
    }

    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), DecodeError> {
        let mut r = Cursor::new(buf);
        let f = Self {
            status: r.u8()?,
            error_code: r.varint()?,
            message: r.string(MAX_MESSAGE)?,
        };
        Ok((f, r.finish()?))
    }
}
