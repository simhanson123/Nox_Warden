//! Bounded TCP admission, without claiming availability against local flooding.
use super::*;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::task::{AbortHandle, JoinSet};

const HEADER: u8 = 0;
const BUSY: u8 = 1;
const VERIFIED: u8 = 2;
const RESPONSE: u8 = 3;
const EVICTED: u8 = 4;

#[derive(Clone)]
pub(crate) struct Phase(Arc<AtomicU8>);
impl Phase {
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(HEADER)))
    }
    fn begin(&self) -> Result<()> {
        self.0
            .compare_exchange(HEADER, BUSY, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Failure::Unavailable)
    }
    pub(super) fn protect(&self) -> Result<()> {
        self.0
            .compare_exchange(BUSY, VERIFIED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Failure::Unavailable)
    }
    fn responded(&self) {
        let _ = self
            .0
            .compare_exchange(BUSY, RESPONSE, Ordering::AcqRel, Ordering::Acquire);
    }
    fn evict(&self) -> bool {
        [HEADER, RESPONSE].into_iter().any(|state| {
            self.0
                .compare_exchange(state, EVICTED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }
}

fn remove(
    tasks: &mut BTreeMap<u64, (AbortHandle, Phase)>,
    result: std::result::Result<u64, tokio::task::JoinError>,
) {
    match result {
        Ok(id) => {
            tasks.remove(&id);
        }
        Err(error) => {
            tasks.retain(|_, (handle, _)| handle.id() != error.id());
        }
    }
}

impl Service {
    /// Serve at most 64 connection tasks and one just-accepted socket. Oldest
    /// unverified headers/responses can be evicted; in-progress work is never
    /// canceled by this policy. Identity is checked by request admission before
    /// a connection becomes protected. This is not a sustained-flood guarantee.
    pub async fn serve(self, listener: tokio::net::TcpListener) -> std::io::Result<()> {
        let router = self.router();
        let mut running = JoinSet::new();
        let mut tasks: BTreeMap<u64, (AbortHandle, Phase)> = BTreeMap::new();
        let mut serial = 0u64;
        loop {
            let (stream, peer) = tokio::select! {
                Some(result)=running.join_next(),if !running.is_empty()=>{remove(&mut tasks,result);continue;},
                accepted=listener.accept()=>accepted?,
            };
            if !peer.ip().is_loopback() {
                continue;
            }
            while let Some(result) = running.try_join_next() {
                remove(&mut tasks, result);
            }
            if running.len() == 64 {
                let victim = tasks
                    .values()
                    .find_map(|(handle, phase)| phase.evict().then(|| handle.clone()));
                let Some(victim) = victim else {
                    continue;
                };
                victim.abort();
                // Join a completion before spawning: canceled tasks and their
                // sockets must not accumulate outside the connection bound.
                if let Some(result) = running.join_next().await {
                    remove(&mut tasks, result);
                }
            }
            serial = serial
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("authority connection serial exhausted"))?;
            let id = serial;
            let phase = Phase::new();
            let request_phase = phase.clone();
            let tower = TowerToHyperService::new(router.clone());
            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    let phase = request_phase.clone();
                    let tower = tower.clone();
                    async move {
                        if phase.begin().is_err() {
                            return Ok::<_, std::convert::Infallible>(secure_headers(
                                Failure::Unavailable.into_response(),
                            ));
                        }
                        request.extensions_mut().insert(phase.clone());
                        let response = hyper::service::Service::call(&tower, request).await;
                        phase.responded();
                        response
                    }
                },
            );
            let handle = running.spawn(async move {
                let mut http = http1::Builder::new();
                http.keep_alive(false)
                    .max_headers(48)
                    .max_buf_size(16384)
                    .header_read_timeout(Duration::from_secs(1))
                    .timer(TokioTimer::new());
                let _ = tokio::time::timeout(
                    Duration::from_secs(30),
                    http.serve_connection(TokioIo::new(stream), service),
                )
                .await;
                id
            });
            tasks.insert(id, (handle, phase));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eviction_cannot_promote_and_busy_work_cannot_be_evicted() {
        let idle = Phase::new();
        assert!(idle.evict());
        assert!(idle.begin().is_err());
        assert!(idle.protect().is_err());
        let busy = Phase::new();
        busy.begin().unwrap();
        assert!(!busy.evict());
        busy.protect().unwrap();
        assert!(!busy.evict());
        let response = Phase::new();
        response.begin().unwrap();
        response.responded();
        assert!(response.evict());
        assert!(response.protect().is_err());
    }
    #[test]
    fn concurrent_header_admission_and_eviction_have_one_winner() {
        for _ in 0..64 {
            let phase = Phase::new();
            let racing = phase.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other = barrier.clone();
            let eviction = std::thread::spawn(move || {
                other.wait();
                racing.evict()
            });
            barrier.wait();
            let started = phase.begin().is_ok();
            let evicted = eviction.join().unwrap();
            assert_ne!(started, evicted);
            assert_eq!(phase.protect().is_ok(), started);
        }
    }
}
