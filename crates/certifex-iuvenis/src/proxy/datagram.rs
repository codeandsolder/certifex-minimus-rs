use std::{
    fs, io,
    net::SocketAddr,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process,
};

use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{UdpSocket, UnixDatagram},
};
use tracing::debug;

pub(super) const UPGRADE_TOKEN: &str = "certifex-datagram";
pub(super) const MAX_DATAGRAM_BYTES: usize = 65_507;
const MAX_CAPSULE_VALUE_BYTES: usize = MAX_DATAGRAM_BYTES + 8;
const DATAGRAM_CAPSULE_TYPE: u64 = 0;

pub(super) enum Target {
    Udp(SocketAddr),
    Unix(PathBuf),
}

enum ConnectedDatagram {
    Udp(UdpSocket),
    Unix(BoundUnixDatagram),
}

struct BoundUnixDatagram {
    socket: UnixDatagram,
    directory: PathBuf,
    socket_path: PathBuf,
}

impl BoundUnixDatagram {
    fn connect(target: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let directory = std::env::temp_dir().join(format!(
                ".certifex-iuvenis-{}-{:016x}",
                process::id(),
                fastrand::u64(..)
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&directory) {
                Ok(()) => {
                    let socket_path = directory.join("client.sock");
                    let socket = match UnixDatagram::bind(&socket_path) {
                        Ok(socket) => socket,
                        Err(error) => {
                            let _ = fs::remove_dir(&directory);
                            return Err(error);
                        }
                    };
                    if let Err(error) = socket.connect(target) {
                        let _ = fs::remove_file(&socket_path);
                        let _ = fs::remove_dir(&directory);
                        return Err(error);
                    }
                    return Ok(Self {
                        socket,
                        directory,
                        socket_path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate unique Unix datagram client path",
        ))
    }
}

impl Drop for BoundUnixDatagram {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_dir(&self.directory);
    }
}

impl ConnectedDatagram {
    async fn connect(target: Target) -> io::Result<Self> {
        match target {
            Target::Udp(address) => {
                let bind = if address.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                } else {
                    SocketAddr::from(([0_u16; 8], 0))
                };
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(address).await?;
                Ok(Self::Udp(socket))
            }
            Target::Unix(path) => Ok(Self::Unix(BoundUnixDatagram::connect(&path)?)),
        }
    }

    async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.send(payload).await,
            Self::Unix(socket) => socket.socket.send(payload).await,
        }
    }

    async fn recv(&self, payload: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(payload).await,
            Self::Unix(socket) => socket.socket.recv(payload).await,
        }
    }
}

pub(super) async fn spawn_relay(
    frontend: OnUpgrade,
    target: Target,
    host: String,
    route_path: String,
) -> io::Result<()> {
    let backend = ConnectedDatagram::connect(target).await?;
    tokio::spawn(async move {
        if let Err(error) = relay(frontend, backend).await {
            debug!(%host, path = %route_path, %error, "datagram tunnel ended with error");
        }
    });
    Ok(())
}

async fn relay(frontend: OnUpgrade, backend: ConnectedDatagram) -> io::Result<()> {
    let frontend = frontend
        .await
        .map_err(|error| io::Error::other(format!("datagram upgrade failed: {error}")))?;
    relay_io(TokioIo::new(frontend), backend).await
}

async fn relay_io<S>(frontend: S, backend: ConnectedDatagram) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(frontend);
    let mut datagram = vec![0_u8; MAX_DATAGRAM_BYTES];

    loop {
        tokio::select! {
            capsule = read_datagram_capsule(&mut reader) => {
                match capsule? {
                    Some(payload) => {
                        let sent = backend.send(&payload).await?;
                        if sent != payload.len() {
                            return Err(io::Error::new(io::ErrorKind::WriteZero, "partial datagram send"));
                        }
                    }
                    None => return Ok(()),
                }
            }
            received = backend.recv(&mut datagram) => {
                let length = received?;
                write_datagram_capsule(&mut writer, &datagram[..length]).await?;
            }
        }
    }
}

async fn read_datagram_capsule<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let Some(capsule_type) = read_quic_varint(reader).await? else {
            return Ok(None);
        };
        let Some(length) = read_quic_varint(reader).await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "capsule length missing",
            ));
        };
        let length = usize::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "capsule too large"))?;
        if length > MAX_CAPSULE_VALUE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capsule exceeds configured limit",
            ));
        }

        let mut value = vec![0_u8; length];
        reader.read_exact(&mut value).await?;
        if capsule_type != DATAGRAM_CAPSULE_TYPE {
            continue;
        }

        let (context_id, context_bytes) = decode_quic_varint(&value)?;
        if context_id != 0 {
            continue;
        }
        let payload = &value[context_bytes..];
        if payload.len() > MAX_DATAGRAM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram exceeds UDP payload limit",
            ));
        }
        return Ok(Some(payload.to_vec()));
    }
}

async fn write_datagram_capsule<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_DATAGRAM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "datagram exceeds UDP payload limit",
        ));
    }
    write_quic_varint(writer, DATAGRAM_CAPSULE_TYPE).await?;
    write_quic_varint(writer, (payload.len() + 1) as u64).await?;
    writer.write_u8(0).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn read_quic_varint<R>(reader: &mut R) -> io::Result<Option<u64>>
where
    R: AsyncRead + Unpin,
{
    let first = match reader.read_u8().await {
        Ok(first) => first,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    let byte_count = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..byte_count {
        value = (value << 8) | u64::from(reader.read_u8().await?);
    }
    Ok(Some(value))
}

fn decode_quic_varint(bytes: &[u8]) -> io::Result<(u64, usize)> {
    let Some(&first) = bytes.first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "QUIC varint missing",
        ));
    };
    let byte_count = 1_usize << (first >> 6);
    if bytes.len() < byte_count {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QUIC varint",
        ));
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &bytes[1..byte_count] {
        value = (value << 8) | u64::from(byte);
    }
    Ok((value, byte_count))
}

async fn write_quic_varint<W>(writer: &mut W, value: u64) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let (byte_count, prefix) = match value {
        0..=63 => (1_usize, 0_u64),
        64..=16_383 => (2, 0x4000),
        16_384..=1_073_741_823 => (4, 0x8000_0000),
        1_073_741_824..=4_611_686_018_427_387_903 => (8, 0xc000_0000_0000_0000),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "value exceeds QUIC varint range",
            ));
        }
    };
    let encoded = value | prefix;
    let bytes = encoded.to_be_bytes();
    writer.write_all(&bytes[8 - byte_count..]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_varints_round_trip_at_boundaries() -> io::Result<()> {
        for value in [
            0_u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut encoded = Vec::new();
            write_quic_varint(&mut encoded, value).await?;
            let (decoded, consumed) = decode_quic_varint(&encoded)?;
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_oversized_capsule_before_reading_payload() -> io::Result<()> {
        let mut wire = Vec::new();
        write_quic_varint(&mut wire, DATAGRAM_CAPSULE_TYPE).await?;
        write_quic_varint(&mut wire, (MAX_CAPSULE_VALUE_BYTES + 1) as u64).await?;
        let result = read_datagram_capsule(&mut wire.as_slice()).await;
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        Ok(())
    }

    #[tokio::test]
    async fn skips_unknown_capsules_and_nonzero_contexts() -> io::Result<()> {
        let mut wire = Vec::new();
        write_quic_varint(&mut wire, 99).await?;
        write_quic_varint(&mut wire, 3).await?;
        wire.extend_from_slice(b"old");
        write_quic_varint(&mut wire, DATAGRAM_CAPSULE_TYPE).await?;
        write_quic_varint(&mut wire, 2).await?;
        wire.extend_from_slice(&[1, b'x']);
        write_datagram_capsule(&mut wire, b"kept").await?;
        assert_eq!(
            read_datagram_capsule(&mut wire.as_slice()).await?,
            Some(b"kept".to_vec())
        );
        Ok(())
    }

    #[tokio::test]
    async fn relays_unix_datagram_round_trip() -> io::Result<()> {
        let directory = std::env::temp_dir().join(format!(
            ".certifex-test-server-{}-{:016x}",
            process::id(),
            fastrand::u64(..)
        ));
        fs::create_dir(&directory)?;
        let server_path = directory.join("server.sock");
        let server = UnixDatagram::bind(&server_path)?;
        let server_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            let (length, peer) = server.recv_from(&mut buffer).await?;
            let peer_path = peer.as_pathname().ok_or_else(|| {
                io::Error::new(io::ErrorKind::AddrNotAvailable, "client had no return path")
            })?;
            server.send_to(&buffer[..length], peer_path).await?;
            io::Result::Ok(())
        });

        let backend = ConnectedDatagram::connect(Target::Unix(server_path.clone())).await?;
        let client_socket_path = match &backend {
            ConnectedDatagram::Unix(bound) => bound.socket_path.clone(),
            ConnectedDatagram::Udp(_) => {
                return Err(io::Error::other("Unix target produced UDP backend"));
            }
        };
        let client_directory = client_socket_path
            .parent()
            .ok_or_else(|| io::Error::other("Unix client socket had no parent directory"))?
            .to_owned();
        let (mut client, relay_side) = tokio::io::duplex(16 * 1024);
        let relay_task = tokio::spawn(relay_io(relay_side, backend));
        write_datagram_capsule(&mut client, b"unix capsule round trip").await?;
        assert_eq!(
            read_datagram_capsule(&mut client).await?,
            Some(b"unix capsule round trip".to_vec())
        );
        drop(client);

        server_task
            .await
            .map_err(|error| io::Error::other(format!("server task failed: {error}")))??;
        relay_task
            .await
            .map_err(|error| io::Error::other(format!("relay task failed: {error}")))??;
        assert!(!client_socket_path.exists());
        assert!(!client_directory.exists());
        fs::remove_file(server_path)?;
        fs::remove_dir(directory)?;
        Ok(())
    }

    #[tokio::test]
    async fn relays_udp_datagram_round_trip() -> io::Result<()> {
        let echo = UdpSocket::bind("127.0.0.1:0").await?;
        let echo_address = echo.local_addr()?;
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2048];
            let (length, peer) = echo.recv_from(&mut buffer).await?;
            echo.send_to(&buffer[..length], peer).await?;
            io::Result::Ok(())
        });

        let backend = ConnectedDatagram::connect(Target::Udp(echo_address)).await?;
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let relay_task = tokio::spawn(relay_io(server, backend));

        write_datagram_capsule(&mut client, b"capsule round trip").await?;
        assert_eq!(
            read_datagram_capsule(&mut client).await?,
            Some(b"capsule round trip".to_vec())
        );
        drop(client);

        echo_task
            .await
            .map_err(|error| io::Error::other(format!("echo task failed: {error}")))??;
        relay_task
            .await
            .map_err(|error| io::Error::other(format!("relay task failed: {error}")))??;
        Ok(())
    }

    #[tokio::test]
    async fn datagram_capsules_preserve_boundaries() -> io::Result<()> {
        let mut wire = Vec::new();
        write_datagram_capsule(&mut wire, b"first").await?;
        write_datagram_capsule(&mut wire, b"second packet").await?;
        let mut reader = wire.as_slice();
        assert_eq!(
            read_datagram_capsule(&mut reader).await?,
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_datagram_capsule(&mut reader).await?,
            Some(b"second packet".to_vec())
        );
        assert_eq!(read_datagram_capsule(&mut reader).await?, None);
        Ok(())
    }
}
