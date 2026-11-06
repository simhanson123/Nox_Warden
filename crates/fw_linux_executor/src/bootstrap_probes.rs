//! Fresh signed peer replies over the exact nonloopback baseline endpoints.
use super::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use fw_authority::{
    BOOTSTRAP_PROBE_REQUEST_SCHEMA, BootstrapPeerResponse, BootstrapProbeKind,
    BootstrapProbeObservation, BootstrapProbeRequest, verify_bootstrap_probe_response,
};
use fw_backend_linux::BootstrapManagementBaseline;
use fw_contracts::parse_strict_with_limit;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

pub(super) fn execute(
    kind: BootstrapProbeKind,
    challenge_hash: &str,
    b: &BootstrapManagementBaseline,
) -> Result<BootstrapProbeObservation> {
    let mut nonce = [0; 32];
    let mut offset = 0;
    while offset < nonce.len() {
        // SAFETY: the remaining nonce slice is writable for exactly this length.
        let count = unsafe {
            libc::getrandom(
                nonce[offset..].as_mut_ptr().cast(),
                nonce.len() - offset,
                libc::GRND_NONBLOCK,
            )
        };
        if count > 0 {
            offset += count as usize;
        } else if count < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return Err(Error::new("BOOTSTRAP_PROBE_NONCE"));
        }
    }
    let request = BootstrapProbeRequest {
        schema_version: BOOTSTRAP_PROBE_REQUEST_SCHEMA.into(),
        challenge_hash: challenge_hash.into(),
        kind,
        nonce: STANDARD.encode(nonce),
    };
    let wire = request.wire_bytes()?;
    let peer: Ipv4Addr = b
        .peer_address
        .parse()
        .map_err(|_| Error::new("BOOTSTRAP_PROBE"))?;
    let port = match kind {
        BootstrapProbeKind::ManagementTcp => b.management_tcp_port,
        BootstrapProbeKind::PositiveUdp => b.positive_udp_port,
        BootstrapProbeKind::NegativeUdp => b.negative_udp_port,
    };
    let address = SocketAddr::from((peer, port));
    let wait = Duration::from_millis(750);
    let deadline = Instant::now() + wait;
    let mut reply = Vec::new();
    if kind == BootstrapProbeKind::ManagementTcp {
        let mut stream = TcpStream::connect_timeout(&address, wait)?;
        stream.set_write_timeout(Some(wait))?;
        stream.write_all(&wire)?;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::new("BOOTSTRAP_PROBE_TIMEOUT"))?;
            stream.set_read_timeout(Some(remaining))?;
            let mut byte = [0];
            if stream.read(&mut byte)? != 1 {
                return Err(Error::new("BOOTSTRAP_PROBE_REPLY"));
            }
            reply.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if reply.len() >= 4096 {
                return Err(Error::new("BOOTSTRAP_PROBE_REPLY"));
            }
        }
    } else {
        let local: Ipv4Addr = b
            .local_address
            .parse()
            .map_err(|_| Error::new("BOOTSTRAP_PROBE"))?;
        let socket = UdpSocket::bind(SocketAddr::from((local, 0)))?;
        socket.connect(address)?;
        socket.set_write_timeout(Some(wait))?;
        socket.set_read_timeout(Some(wait))?;
        match socket.send(&wire) {
            Ok(length) if length == wire.len() => {}
            // The installed output hook was observed refusing this send. Keep
            // its exact errno and zero sent bytes; do not fabricate a timeout.
            Err(error)
                if kind == BootstrapProbeKind::NegativeUdp
                    && error.raw_os_error() == Some(libc::EPERM) =>
            {
                return Ok(BootstrapProbeObservation {
                    request,
                    response: None,
                    bytes_sent: 0,
                    bytes_received: 0,
                    outcome: "local_send_denied".into(),
                    os_error: Some(libc::EPERM),
                });
            }
            _ => return Err(Error::new("BOOTSTRAP_PROBE_SEND")),
        }
        let mut bytes = [0; 4097];
        match socket.recv(&mut bytes) {
            Ok(length) => reply.extend_from_slice(&bytes[..length]),
            Err(error)
                if kind == BootstrapProbeKind::NegativeUdp
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
            {
                return Ok(BootstrapProbeObservation {
                    request,
                    response: None,
                    bytes_sent: wire.len() as u64,
                    bytes_received: 0,
                    outcome: "timeout".into(),
                    os_error: None,
                });
            }
            Err(_) => return Err(Error::new("BOOTSTRAP_PROBE_REPLY")),
        }
    }
    if kind == BootstrapProbeKind::NegativeUdp || reply.len() > 4096 || reply.last() != Some(&b'\n')
    {
        return Err(Error::new("BOOTSTRAP_PROBE_REPLY"));
    }
    let response: BootstrapPeerResponse = parse_strict_with_limit(&reply[..reply.len() - 1], 4096)
        .map_err(|_| Error::new("BOOTSTRAP_PROBE_REPLY"))?;
    if response.wire_bytes()? != reply {
        return Err(Error::new("BOOTSTRAP_PROBE_REPLY"));
    }
    verify_bootstrap_probe_response(&request, &response, b)?;
    Ok(BootstrapProbeObservation {
        request,
        response: Some(response),
        bytes_sent: wire.len() as u64,
        bytes_received: reply.len() as u64,
        outcome: "reply".into(),
        os_error: None,
    })
}
