//! Message framing: length-prefixed binary frames.
//!
//! ZeroNet uses msgpack over raw TCP with implicit framing. This module
//! provides a clean, length-prefixed binary framing that is easier to
//! buffer and more robust against stream corruption.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 4-byte big-endian length prefix.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Write a single frame (length + payload) to the stream.
pub async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), NetErr> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// Read a single frame from the stream.
pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, NetErr> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(NetErr::OversizedFrame(len));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[derive(Debug, thiserror::Error)]
pub enum NetErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes")]
    OversizedFrame(usize),
}
