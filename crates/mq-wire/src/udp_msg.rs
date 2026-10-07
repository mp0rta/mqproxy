// spec §2.2
//! The fixed 9-byte header that prefixes every UDP payload carried in a QUIC
//! DATAGRAM frame (all big-endian) and the pure fragment split. Nothing here
//! allocates; `split` hands out slices that borrow the caller's payload.

pub const UDP_MSG_HDR: usize = 9;

/// `session_id u32 | packet_id u16 | flags u8 | frag_id u8 | frag_count u8`.
/// `flags` is 0 on transmit and ignored on receive (forward compatibility).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UdpMsgHdr {
    pub session_id: u32,
    pub packet_id: u16,
    pub flags: u8,
    pub frag_id: u8,
    /// 1 = unfragmented.
    pub frag_count: u8,
}

impl UdpMsgHdr {
    pub fn encode(&self, out: &mut [u8; UDP_MSG_HDR]) {
        out[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        out[4..6].copy_from_slice(&self.packet_id.to_be_bytes());
        out[6] = self.flags;
        out[7] = self.frag_id;
        out[8] = self.frag_count;
    }

    /// Reads the first 9 bytes of `buf`; `None` if it is shorter. Trailing
    /// bytes (the payload) are ignored.
    pub fn decode(buf: &[u8]) -> Option<UdpMsgHdr> {
        let b = buf.first_chunk::<UDP_MSG_HDR>()?;
        Some(UdpMsgHdr {
            session_id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            packet_id: u16::from_be_bytes([b[4], b[5]]),
            flags: b[6],
            frag_id: b[7],
            frag_count: b[8],
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SplitError {
    /// More than 255 fragments would be needed (`frag_count` is a u8).
    TooManyFrags,
    ZeroMss,
}

/// Calls `emit(hdr, slice)` once per fragment of at most `mss_payload` bytes,
/// in order. An empty payload emits exactly one empty fragment. On error
/// nothing is emitted.
pub fn split(
    sid: u32,
    packet_id: u16,
    payload: &[u8],
    mss_payload: usize,
    mut emit: impl FnMut(&UdpMsgHdr, &[u8]),
) -> Result<(), SplitError> {
    if mss_payload == 0 {
        return Err(SplitError::ZeroMss);
    }
    let nfrags = payload.len().div_ceil(mss_payload).max(1);
    let frag_count = u8::try_from(nfrags).map_err(|_| SplitError::TooManyFrags)?;
    let mut hdr = UdpMsgHdr {
        session_id: sid,
        packet_id,
        flags: 0,
        frag_id: 0,
        frag_count,
    };
    if payload.is_empty() {
        emit(&hdr, payload);
        return Ok(());
    }
    for (i, chunk) in payload.chunks(mss_payload).enumerate() {
        hdr.frag_id = i as u8; // i < nfrags <= 255
        emit(&hdr, chunk);
    }
    Ok(())
}
