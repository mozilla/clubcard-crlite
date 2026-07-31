use clubcard::{Clubcard, ClubcardIndex, ClubcardIndexEntry};

use crate::W;
use crate::query::{CRLiteCoverage, ClubcardError};

/// A type with a TLS-like binary encoding.
pub(crate) trait Codec: Sized {
    /// Append the encoded form of `self` to `buf`.
    ///
    /// Fails if a length or item count does not fit in its length prefix.
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError>;

    /// Parse one value of `Self` from the front of `buf`.
    ///
    /// Returns the parsed value together with the unconsumed remainder of `buf`.
    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError>;
}

// ```
// struct {
//     CRLiteCoverage universe;
//     ClubcardIndex  index;
//     FilterColumn   approx_filter<count>;   // uint8 count, then `count` columns
//     FilterColumn   exact_filter;
// } Clubcard;
// ```
//
// where `FilterColumn` is `uint64 words<count>` (a uint32 count followed by
// that many big-endian words).
impl Codec for Clubcard<W, CRLiteCoverage, ()> {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
        self.universe.encode(buf)?;
        self.index.encode(buf)?;

        encode_len::<1>(self.approx_filter.len(), buf)?;
        for column in &self.approx_filter {
            encode_seq::<4, u64>(column, buf)?;
        }

        encode_seq::<4, u64>(&self.exact_filter, buf)
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (universe, buf) = CRLiteCoverage::read(buf)?;
        let (index, buf) = ClubcardIndex::read(buf)?;
        let (column_count, mut buf) = read_len::<1>(buf)?;

        let mut approx_filter = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let (column, rest) = read_u64_seq(buf)?;
            approx_filter.push(column);
            buf = rest;
        }

        let (exact_filter, buf) = read_u64_seq(buf)?;

        Ok((
            Clubcard {
                universe,
                partition: (),
                index,
                approx_filter,
                exact_filter,
            },
            buf,
        ))
    }
}

// ```
// struct {
//     uint8  len;
//     opaque serial[len];
// } Exception;                        // serial as opaque<0..2^8-1>
//
// struct {
//     uint32    approx_filter_m;
//     uint8     approx_filter_rank;
//     uint32    approx_filter_offset;
//     uint32    exact_filter_m;
//     uint32    exact_filter_offset;
//     uint8     inverted;
//     Exception exceptions<count>;     // uint16 count, then `count` serials
// } ClubcardIndexEntry;
// ```
impl Codec for ClubcardIndexEntry {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
        let Self {
            approx_filter_m,
            approx_filter_rank,
            approx_filter_offset,
            exact_filter_m,
            exact_filter_offset,
            inverted,
            exceptions,
        } = self;

        encode_usize_as_u32(*approx_filter_m, "approx_filter_m", buf)?;
        match u8::try_from(*approx_filter_rank) {
            Ok(rank) => rank.encode(buf)?,
            Err(_) => {
                return Err(ClubcardError::Serialize(
                    format!("approx_filter_rank value {approx_filter_rank} does not fit in u8")
                        .into(),
                ));
            }
        }
        encode_usize_as_u32(*approx_filter_offset, "approx_filter_offset", buf)?;
        encode_usize_as_u32(*exact_filter_m, "exact_filter_m", buf)?;
        encode_usize_as_u32(*exact_filter_offset, "exact_filter_offset", buf)?;

        u8::from(*inverted).encode(buf)?;
        encode_len::<2>(exceptions.len(), buf)?;
        for serial in exceptions {
            encode_vec::<1>(serial, buf)?;
        }

        Ok(())
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (approx_filter_m, buf) = u32::read(buf)?;
        let (approx_filter_rank, buf) = u8::read(buf)?;
        let (approx_filter_offset, buf) = u32::read(buf)?;
        let (exact_filter_m, buf) = u32::read(buf)?;
        let (exact_filter_offset, buf) = u32::read(buf)?;
        let (inverted, buf) = u8::read(buf)?;

        let (count, mut buf) = read_len::<2>(buf)?;
        let mut exceptions = Vec::with_capacity(count);
        for _ in 0..count {
            let (serial, rest) = read_vec::<1>(buf)?;
            exceptions.push(serial.to_vec());
            buf = rest;
        }

        Ok((
            ClubcardIndexEntry {
                approx_filter_m: approx_filter_m as usize,
                exact_filter_m: exact_filter_m as usize,
                approx_filter_rank: approx_filter_rank as usize,
                approx_filter_offset: approx_filter_offset as usize,
                exact_filter_offset: exact_filter_offset as usize,
                inverted: inverted != 0,
                exceptions,
            },
            buf,
        ))
    }
}

// `uint64`, big-endian.
impl Codec for u64 {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (bytes, rest) = buf.split_first_chunk().ok_or(ClubcardError::Deserialize(
            "not enough bytes for u64".into(),
        ))?;
        Ok((u64::from_be_bytes(*bytes), rest))
    }
}

// `uint32`, big-endian.
impl Codec for u32 {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(())
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (bytes, rest) = buf.split_first_chunk().ok_or(ClubcardError::Deserialize(
            "not enough bytes for u32".into(),
        ))?;
        Ok((u32::from_be_bytes(*bytes), rest))
    }
}

// `uint8`.
impl Codec for u8 {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
        buf.push(*self);
        Ok(())
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (&val, rest) = buf
            .split_first()
            .ok_or(ClubcardError::Deserialize("not enough bytes for u8".into()))?;
        Ok((val, rest))
    }
}

/// Append an `N`-byte big-endian length (or item count) prefix.
///
/// Fails if `len` does not fit in `N` bytes.
pub(crate) fn encode_len<const N: usize>(
    len: usize,
    buf: &mut Vec<u8>,
) -> Result<(), ClubcardError> {
    let bytes = len.to_be_bytes();
    let (overflow, prefix) = bytes.split_at(size_of::<usize>() - N);
    for &byte in overflow {
        if byte != 0 {
            return Err(ClubcardError::Serialize(
                format!("length {len} does not fit in a {N}-byte prefix").into(),
            ));
        }
    }

    buf.extend_from_slice(prefix);
    Ok(())
}

/// Read an `N`-byte big-endian length (or item count) prefix.
pub(crate) fn read_len<const N: usize>(buf: &[u8]) -> Result<(usize, &[u8]), ClubcardError> {
    let (len, rest) = buf
        .split_first_chunk::<N>()
        .ok_or(ClubcardError::Deserialize(
            "not enough bytes for length".into(),
        ))?;

    let mut padded = [0u8; size_of::<usize>()];
    padded[size_of::<usize>() - N..].copy_from_slice(len);
    Ok((usize::from_be_bytes(padded), rest))
}

/// opaque content<0..2^(8*N)-1>: an `N`-byte byte-length prefix followed by the bytes.
pub(crate) fn encode_vec<const N: usize>(
    content: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), ClubcardError> {
    encode_len::<N>(content.len(), buf)?;
    buf.extend_from_slice(content);
    Ok(())
}

pub(crate) fn read_vec<const N: usize>(buf: &[u8]) -> Result<(&[u8], &[u8]), ClubcardError> {
    let (len, rest) = read_len::<N>(buf)?;
    rest.split_at_checked(len).ok_or(ClubcardError::Deserialize(
        "not enough bytes for vector content".into(),
    ))
}

/// `T items<count>`: an `N`-byte item *count* prefix followed by that many encoded `T`s.
pub(crate) fn encode_seq<const N: usize, T: Codec>(
    items: &[T],
    buf: &mut Vec<u8>,
) -> Result<(), ClubcardError> {
    encode_len::<N>(items.len(), buf)?;
    for item in items {
        item.encode(buf)?;
    }

    Ok(())
}

/// Read `u64 items<count>` sequence; a `u32` item *count* prefix followed by that many `u64`s.
pub(crate) fn read_u64_seq(buf: &[u8]) -> Result<(Vec<u64>, &[u8]), ClubcardError> {
    let (count, buf) = read_len::<4>(buf)?;

    let byte_len = count
        .checked_mul(size_of::<u64>())
        .ok_or(ClubcardError::Deserialize(
            "not enough bytes for u64 sequence length".into(),
        ))?;
    let (words, rest) = buf
        .split_at_checked(byte_len)
        .ok_or(ClubcardError::Deserialize(
            "not enough bytes for u64 sequence data".into(),
        ))?;

    let mut items = Vec::with_capacity(count);
    // Use `as_chunks()` when MSRV is 1.88 or later
    items.extend(words.chunks_exact(size_of::<u64>()).map(|chunk| {
        u64::from_be_bytes(<[u8; size_of::<u64>()]>::try_from(chunk).expect("chunk is u64-sized"))
    }));

    Ok((items, rest))
}

/// Encode `number` as a big-endian `uint32`.
///
/// Fails if `number` does not fit in a `u32`, naming `name` in the error.
fn encode_usize_as_u32(number: usize, name: &str, buf: &mut Vec<u8>) -> Result<(), ClubcardError> {
    match u32::try_from(number) {
        Ok(number) => number.encode(buf),
        Err(_) => Err(ClubcardError::Serialize(
            format!("{name} value {number} does not fit in u32").into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_len_rejects_oversized_lengths() {
        let mut buf = Vec::new();
        encode_len::<1>(u8::MAX as usize, &mut buf).unwrap();
        assert_eq!(buf, [0xff]);
        assert!(encode_len::<1>(u8::MAX as usize + 1, &mut Vec::new()).is_err());

        let mut buf = Vec::new();
        encode_len::<2>(u16::MAX as usize, &mut buf).unwrap();
        assert_eq!(buf, [0xff, 0xff]);
        assert!(encode_len::<2>(u16::MAX as usize + 1, &mut Vec::new()).is_err());
    }

    #[test]
    fn index_entry_rejects_oversized_serial() {
        let mut entry = ClubcardIndexEntry {
            approx_filter_m: 0,
            approx_filter_rank: 0,
            approx_filter_offset: 0,
            exact_filter_m: 0,
            exact_filter_offset: 0,
            inverted: false,
            exceptions: vec![vec![0u8; u8::MAX as usize]],
        };
        entry.encode(&mut Vec::new()).unwrap();

        entry.exceptions = vec![vec![0u8; u8::MAX as usize + 1]];
        assert!(entry.encode(&mut Vec::new()).is_err());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn index_entry_rejects_oversized_offset() {
        let mut entry = ClubcardIndexEntry {
            approx_filter_m: 0,
            approx_filter_rank: 0,
            approx_filter_offset: 0,
            exact_filter_m: 0,
            exact_filter_offset: u32::MAX as usize,
            inverted: false,
            exceptions: Vec::new(),
        };
        entry.encode(&mut Vec::new()).unwrap();

        entry.exact_filter_offset = u32::MAX as usize + 1;
        assert!(entry.encode(&mut Vec::new()).is_err());
    }

    #[test]
    fn index_rejects_block_id_that_is_not_32_bytes() {
        let entry = || ClubcardIndexEntry {
            approx_filter_m: 0,
            approx_filter_rank: 0,
            approx_filter_offset: 0,
            exact_filter_m: 0,
            exact_filter_offset: 0,
            inverted: false,
            exceptions: Vec::new(),
        };

        let mut index = ClubcardIndex::new();
        index.insert(vec![0u8; 32], entry());
        index.encode(&mut Vec::new()).unwrap();

        let mut index = ClubcardIndex::new();
        index.insert(vec![0u8; 31], entry());
        assert!(index.encode(&mut Vec::new()).is_err());
    }

    #[test]
    fn index_entry_rejects_oversized_exception_count() {
        let mut entry = ClubcardIndexEntry {
            approx_filter_m: 0,
            approx_filter_rank: 0,
            approx_filter_offset: 0,
            exact_filter_m: 0,
            exact_filter_offset: 0,
            inverted: false,
            exceptions: vec![Vec::new(); u16::MAX as usize],
        };
        entry.encode(&mut Vec::new()).unwrap();

        entry.exceptions = vec![Vec::new(); u16::MAX as usize + 1];
        assert!(entry.encode(&mut Vec::new()).is_err());
    }
}
