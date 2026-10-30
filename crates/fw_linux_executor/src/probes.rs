use crate::{Error, Result, native};
use fw_linux_executor::{ProbeObservation, ProbeSpec};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub fn validate(specifications: &[ProbeSpec]) -> Result<()> {
    if specifications.len() < 3
        || specifications.len() > 16
        || !specifications
            .iter()
            .any(|p| p.protocol == "tcp" && p.expect_reply)
        || !specifications
            .iter()
            .any(|p| p.protocol == "udp" && p.expect_reply)
        || !specifications.iter().any(|p| !p.expect_reply)
    {
        return Err(Error::new("PROBE_COVERAGE"));
    }
    let mut names = std::collections::BTreeSet::new();
    for p in specifications {
        if p.name.is_empty()
            || p.name.len() > 64
            || !p
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || !names.insert(&p.name)
            || !["ipv4", "ipv6"].contains(&p.family.as_str())
            || !["tcp", "udp"].contains(&p.protocol.as_str())
            || p.port == 0
        {
            return Err(Error::new("PROBE_SPECIFICATION"));
        }
    }
    Ok(())
}
fn timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}
pub fn execute(specification: &ProbeSpec) -> Result<ProbeObservation> {
    native::guard()?;
    let address = if specification.family == "ipv4" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    };
    let address = SocketAddr::new(address, specification.port);
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let data = nonce.as_bytes();
    let wait = Duration::from_millis(350);
    let mut reply = [0u8; 128];
    let mut sent = 0;
    let received = if specification.protocol == "tcp" {
        match TcpStream::connect_timeout(&address, wait) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(wait))?;
                stream.set_write_timeout(Some(wait))?;
                stream.write_all(data)?;
                sent = data.len();
                stream
                    .read_exact(&mut reply[..data.len()])
                    .map(|_| data.len())
            }
            Err(error) => Err(error),
        }
    } else {
        let socket = UdpSocket::bind(SocketAddr::new(address.ip(), 0))?;
        socket.connect(address)?;
        socket.set_read_timeout(Some(wait))?;
        socket.set_write_timeout(Some(wait))?;
        sent = socket.send(data)?;
        socket.recv(&mut reply)
    };
    let (received, outcome) = match received {
        Ok(length) if specification.expect_reply && &reply[..length] == data => (length, "reply"),
        Err(error) if !specification.expect_reply && timeout(&error) => (0, "timeout"),
        _ => return Err(Error::new("PACKET_PROBE_FAILED")),
    };
    Ok(ProbeObservation {
        specification: specification.clone(),
        nonce,
        bytes_sent: sent,
        bytes_received: received,
        outcome: outcome.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec(name: &str, protocol: &str, expect_reply: bool) -> ProbeSpec {
        ProbeSpec {
            name: name.into(),
            family: "ipv4".into(),
            protocol: protocol.into(),
            port: 18080,
            expect_reply,
        }
    }
    #[test]
    fn probe_admission_requires_positive_and_negative_coverage() {
        let mut valid = vec![
            spec("tcp", "tcp", true),
            spec("udp", "udp", true),
            spec("deny", "tcp", false),
        ];
        assert!(validate(&valid).is_ok());
        valid[2].expect_reply = true;
        assert!(validate(&valid).is_err());
    }
    #[test]
    fn rejects_duplicate_unsupported_and_unbounded_probes() {
        let mut valid = vec![
            spec("tcp", "tcp", true),
            spec("udp", "udp", true),
            spec("deny", "tcp", false),
        ];
        valid[2].name = "tcp".into();
        assert!(validate(&valid).is_err());
        valid[2].name = "deny".into();
        valid[2].family = "external".into();
        assert!(validate(&valid).is_err());
        valid[2].family = "ipv4".into();
        valid[2].port = 0;
        assert!(validate(&valid).is_err());
    }
}
