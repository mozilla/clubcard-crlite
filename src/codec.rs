use clubcard::{Clubcard, ClubcardIndex, ClubcardIndexEntry};

use crate::W;
use crate::query::{CRLiteCoverage, ClubcardError};

/// A type with a TLS-like binary encoding.
pub(crate) trait Codec: Sized {
    /// Append the encoded form of `self` to `buf`.
    fn encode(&self, buf: &mut Vec<u8>);

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
    fn encode(&self, buf: &mut Vec<u8>) {
        self.universe.encode(buf);
        self.index.encode(buf);

        encode_len::<1>(self.approx_filter.len(), buf);
        for column in &self.approx_filter {
            encode_seq::<4, u64>(column, buf);
        }

        encode_seq::<4, u64>(&self.exact_filter, buf);
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
    fn encode(&self, buf: &mut Vec<u8>) {
        (self.approx_filter_m as u32).encode(buf);
        (self.approx_filter_rank as u8).encode(buf);
        (self.approx_filter_offset as u32).encode(buf);
        (self.exact_filter_m as u32).encode(buf);
        (self.exact_filter_offset as u32).encode(buf);
        (self.inverted as u8).encode(buf);

        encode_len::<2>(self.exceptions.len(), buf);
        for serial in &self.exceptions {
            encode_vec::<1>(serial, buf);
        }
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
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
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
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
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
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
    }

    fn read(buf: &[u8]) -> Result<(Self, &[u8]), ClubcardError> {
        let (&val, rest) = buf
            .split_first()
            .ok_or(ClubcardError::Deserialize("not enough bytes for u8".into()))?;
        Ok((val, rest))
    }
}

/// Append an `N`-byte big-endian length (or item count) prefix.
pub(crate) fn encode_len<const N: usize>(len: usize, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&len.to_be_bytes()[size_of::<usize>() - N..]);
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
pub(crate) fn encode_vec<const N: usize>(content: &[u8], buf: &mut Vec<u8>) {
    encode_len::<N>(content.len(), buf);
    buf.extend_from_slice(content);
}

pub(crate) fn read_vec<const N: usize>(buf: &[u8]) -> Result<(&[u8], &[u8]), ClubcardError> {
    let (len, rest) = read_len::<N>(buf)?;
    rest.split_at_checked(len).ok_or(ClubcardError::Deserialize(
        "not enough bytes for vector content".into(),
    ))
}

/// `T items<count>`: an `N`-byte item *count* prefix followed by that many encoded `T`s.
pub(crate) fn encode_seq<const N: usize, T: Codec>(items: &[T], buf: &mut Vec<u8>) {
    encode_len::<N>(items.len(), buf);
    for item in items {
        item.encode(buf);
    }
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
