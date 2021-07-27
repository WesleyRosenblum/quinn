use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use hdrhistogram::Histogram;
use serde::{self, ser::SerializeStruct, Serialize, Serializer};
use structopt::StructOpt;
use tokio::sync::Semaphore;
use tracing::{debug, error, info};

use perf::bind_socket;
use quinn::StreamId;
use std::{
    ops::Deref,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Connects to a QUIC perf server and maintains a specified pattern of requests until interrupted
#[derive(StructOpt)]
#[structopt(name = "client")]
struct Opt {
    /// Host to connect to
    #[structopt(default_value = "localhost:4433")]
    host: String,
    /// Override DNS resolution for host
    #[structopt(long)]
    ip: Option<IpAddr>,
    /// Number of unidirectional requests to maintain concurrently
    #[structopt(long, default_value = "0")]
    uni_requests: u64,
    /// Number of bidirectional requests to maintain concurrently
    #[structopt(long, default_value = "1")]
    bi_requests: u64,
    /// Number of bytes to request
    #[structopt(long, default_value = "1048576")]
    download_size: u64,
    /// Number of bytes to transmit, in addition to the request header
    #[structopt(long, default_value = "1048576")]
    upload_size: u64,
    /// Whether to skip certificate validation
    #[structopt(long)]
    insecure: bool,
    /// The time to run in seconds
    #[structopt(long, default_value = "60")]
    duration: u64,
    /// The interval in seconds at which stats are reported
    #[structopt(long, default_value = "1")]
    interval: u64,
    /// Send buffer size in bytes
    #[structopt(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[structopt(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Specify the local socket address
    #[structopt(long)]
    local_addr: Option<SocketAddr>,
    /// Whether to print connection statistics
    #[structopt(long)]
    conn_stats: bool,
    /// Whether to output JSON statistics
    #[structopt(long)]
    json: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::from_args();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let mut host_parts = opt.host.split(':');
    let host_name = host_parts.next().unwrap();
    let host_port = host_parts
        .next()
        .map_or(Ok(443), |x| x.parse())
        .context("parsing port")?;
    let addr = match opt.ip {
        None => tokio::net::lookup_host(&opt.host)
            .await
            .context("resolving host")?
            .next()
            .unwrap(),
        Some(ip) => SocketAddr::new(ip, host_port),
    };

    info!("connecting to {} at {}", host_name, addr);

    let bind_addr = opt.local_addr.unwrap_or_else(|| {
        let unspec = if addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        SocketAddr::new(unspec, 0)
    });

    info!("local addr {:?}", bind_addr);

    let socket = bind_socket(bind_addr, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::EndpointBuilder::default();

    let (endpoint, _) = endpoint.with_socket(socket).context("binding endpoint")?;

    let mut cfg = quinn::ClientConfigBuilder::default();
    cfg.protocols(&[b"perf"]);
    let mut cfg = cfg.build();

    let tls_config: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    if opt.insecure {
        tls_config
            .dangerous()
            .set_certificate_verifier(SkipServerVerification::new());
    }
    // Configure cipher suites for efficiency
    tls_config.ciphersuites.clear();
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_128_GCM_SHA256);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_AES_256_GCM_SHA384);
    tls_config
        .ciphersuites
        .push(&rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256);

    let stats = Arc::new(Mutex::new(Stats::default()));

    let quinn::NewConnection {
        connection,
        uni_streams,
        ..
    } = endpoint
        .connect_with(cfg, &addr, &host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let acceptor = UniAcceptor(Arc::new(tokio::sync::Mutex::new(uni_streams)));

    let drive_fut = async {
        tokio::try_join!(
            drive_uni(
                connection.clone(),
                acceptor,
                stats.clone(),
                opt.uni_requests,
                opt.upload_size,
                opt.download_size
            ),
            drive_bi(
                connection.clone(),
                stats.clone(),
                opt.bi_requests,
                opt.upload_size,
                opt.download_size
            )
        )
    };

    let print_fut = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            {
                if !opt.json {
                    let guard = stats.lock().unwrap();
                    guard.print();
                    if opt.conn_stats {
                        println!("{:?}\n", connection.stats());
                    }
                }
            }
        }
    };

    let report_fut = async {
        let interval_duration = Duration::from_secs(opt.interval);
        loop {
            let start = Instant::now();
            tokio::time::sleep(interval_duration).await;
            {
                let mut guard = stats.lock().unwrap();
                guard.report_interval(start);
            }
        }
    };

    tokio::select! {
        _ = drive_fut => {}
        _ = print_fut => {}
        _ = report_fut => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
            connection.close(0u32.into(), b"interrupted");
        }
        _ = tokio::time::sleep(Duration::from_secs(opt.duration)) => {
            info!("shutting down");
            connection.close(0u32.into(), b"done");
        }
    }

    endpoint.wait_idle().await;

    if opt.json {
        println!("{}", serde_json::to_string(&stats.lock().unwrap().deref())?);
    }

    Ok(())
}

async fn drain_stream(
    mut stream: quinn::RecvStream,
    stats: Arc<Mutex<Stats>>,
    request_stats: &mut RequestStats,
) -> Result<()> {
    #[rustfmt::skip]
    let mut bufs = [
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
    ];
    let recv_stream_stats = Arc::new(StreamStats::new(stream.id(), false));
    stats
        .lock()
        .unwrap()
        .stream_stats
        .get_mut()
        .unwrap()
        .push(recv_stream_stats.clone());

    while let Some(size) = stream.read_chunks(&mut bufs[..]).await? {
        if request_stats.first_byte.is_none() {
            request_stats.first_byte = Some(Instant::now());
        }
        let bytes_received = bufs[..size].iter().map(|b| b.len()).sum();
        recv_stream_stats
            .bytes
            .fetch_add(bytes_received, Ordering::Relaxed);
    }

    let now = Instant::now();
    if request_stats.first_byte.is_none() {
        request_stats.first_byte = Some(now);
    }
    request_stats.download_end = Some(now);
    recv_stream_stats.finished.store(true, Ordering::Relaxed);

    debug!("response finished on {}", stream.id());
    Ok(())
}

async fn drive_uni(
    connection: quinn::Connection,
    acceptor: UniAcceptor,
    stats: Arc<Mutex<Stats>>,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut request_stats = RequestStats::new(upload, download);
        let send = connection.open_uni().await?;
        let acceptor = acceptor.clone();
        let stats = stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_uni(
                send,
                acceptor,
                upload,
                download,
                stats.clone(),
                &mut request_stats,
            )
            .await
            {
                error!("sending request failed: {:#}", e);
            } else {
                request_stats.success = true;
            }

            {
                let mut guard = stats.lock().unwrap();
                guard.record(request_stats);
            }

            drop(permit);
        });
    }
}

async fn request_uni(
    send: quinn::SendStream,
    acceptor: UniAcceptor,
    upload: u64,
    download: u64,
    stats: Arc<Mutex<Stats>>,
    request_stats: &mut RequestStats,
) -> Result<()> {
    request(send, upload, download, stats.clone(), request_stats).await?;
    let recv = {
        let mut guard = acceptor.0.lock().await;
        guard
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("End of stream"))
    }??;
    drain_stream(recv, stats, request_stats).await?;
    Ok(())
}

async fn request(
    mut send: quinn::SendStream,
    mut upload: u64,
    download: u64,
    stats: Arc<Mutex<Stats>>,
    request_stats: &mut RequestStats,
) -> Result<()> {
    request_stats.upload_start = Some(Instant::now());
    send.write_all(&download.to_be_bytes()).await?;

    if upload == 0 {
        send.finish().await?;
        return Ok(());
    }

    let send_stream_stats = Arc::new(StreamStats::new(send.id(), true));

    stats
        .lock()
        .unwrap()
        .stream_stats
        .get_mut()
        .unwrap()
        .push(send_stream_stats.clone());

    const DATA: [u8; 1024 * 1024] = [42; 1024 * 1024];
    while upload > 0 {
        let chunk_len = upload.min(DATA.len() as u64);
        send.write_chunk(Bytes::from_static(&DATA[..chunk_len as usize]))
            .await
            .context("sending response")?;
        send_stream_stats
            .bytes
            .fetch_add(chunk_len as usize, Ordering::Relaxed);
        upload -= chunk_len;
    }
    send.finish().await?;
    send_stream_stats.finished.store(true, Ordering::Relaxed);

    let now = Instant::now();
    request_stats.download_start = Some(now);

    debug!("upload finished on {}", send.id());
    Ok(())
}

async fn drive_bi(
    connection: quinn::Connection,
    stats: Arc<Mutex<Stats>>,
    concurrency: u64,
    upload: u64,
    download: u64,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(concurrency as usize));

    loop {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let mut request_stats = RequestStats::new(upload, download);
        let (send, recv) = connection.open_bi().await?;
        let stats = stats.clone();

        debug!("sending request on {}", send.id());
        tokio::spawn(async move {
            if let Err(e) = request_bi(
                send,
                recv,
                upload,
                download,
                stats.clone(),
                &mut request_stats,
            )
            .await
            {
                error!("request failed: {:#}", e);
            } else {
                request_stats.success = true;
            }

            {
                let mut guard = stats.lock().unwrap();
                guard.record(request_stats);
            }

            drop(permit);
        });
    }
}

async fn request_bi(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    upload: u64,
    download: u64,
    stats: Arc<Mutex<Stats>>,
    request_status: &mut RequestStats,
) -> Result<()> {
    request(send, upload, download, stats.clone(), request_status).await?;
    drain_stream(recv, stats, request_status).await?;
    Ok(())
}

#[derive(Clone)]
struct UniAcceptor(Arc<tokio::sync::Mutex<quinn::IncomingUniStreams>>);

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

struct StreamStats {
    id: StreamId,
    bytes: AtomicUsize,
    sender: bool,
    finished: AtomicBool,
}

impl StreamStats {
    pub fn new(id: StreamId, sender: bool) -> Self {
        Self {
            id,
            bytes: Default::default(),
            sender,
            finished: Default::default(),
        }
    }
}

struct RequestStats {
    start: Instant,
    upload_start: Option<Instant>,
    download_start: Option<Instant>,
    first_byte: Option<Instant>,
    download_end: Option<Instant>,
    upload_size: u64,
    download_size: u64,
    success: bool,
}

impl RequestStats {
    pub fn new(upload_size: u64, download_size: u64) -> Self {
        Self {
            start: Instant::now(),
            upload_start: None,
            download_start: None,
            first_byte: None,
            upload_size,
            download_size,
            download_end: None,
            success: false,
        }
    }
}

struct Interval {
    streams: Vec<StreamIntervalStats>,
    recv_stream_sum: StreamIntervalSumStats,
    send_stream_sum: StreamIntervalSumStats,
    period: IntervalPeriod,
}

impl Interval {
    pub fn new(start: Duration, end: Duration) -> Self {
        let period = IntervalPeriod {
            start: start.as_secs_f64(),
            end: end.as_secs_f64(),
            seconds: (end - start).as_secs_f64(),
        };

        Self {
            streams: vec![],
            recv_stream_sum: StreamIntervalSumStats::new(period),
            send_stream_sum: StreamIntervalSumStats::new(period),
            period,
        }
    }

    pub fn add_stream_stats(&mut self, stream_stats: Arc<StreamStats>) {
        let bytes = stream_stats.bytes.swap(0, Ordering::Relaxed);
        if stream_stats.sender {
            self.send_stream_sum.bytes += bytes;
        } else {
            self.recv_stream_sum.bytes += bytes;
        }
        self.streams.push(StreamIntervalStats {
            id: stream_stats.id.0,
            start: self.period.start,
            end: self.period.end,
            seconds: self.period.seconds,
            bytes,
            bits_per_second: bytes as f64 * 8.0 / self.period.seconds,
            sender: stream_stats.sender,
        })
    }
}

impl Serialize for Interval {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Interval", 2)?;
        state.serialize_field("streams", &self.streams)?;
        // iperf3 outputs duplicate "sum" entries when run in bidirectional mode
        // serde does not support duplicate keys, so only output one of the sums
        if self.send_stream_sum.bytes > 0 {
            state.serialize_field("sum", &self.send_stream_sum)?;
        } else {
            state.serialize_field("sum", &self.recv_stream_sum)?;
        }
        state.end()
    }
}

#[derive(Copy, Clone, Serialize)]
struct IntervalPeriod {
    start: f64,
    end: f64,
    seconds: f64,
}

#[derive(Serialize)]
struct StreamIntervalStats {
    id: u64,
    start: f64,
    end: f64,
    seconds: f64,
    bytes: usize,
    bits_per_second: f64,
    sender: bool,
}

#[derive(Serialize)]
struct StreamIntervalSumStats {
    bytes: usize,
    start: f64,
    end: f64,
    seconds: f64,
    bits_per_second: f64,
    sender: bool,
}

impl StreamIntervalSumStats {
    fn new(period: IntervalPeriod) -> Self {
        Self {
            bytes: 0,
            start: period.start,
            end: period.end,
            seconds: period.seconds,
            bits_per_second: 0.0,
            sender: false,
        }
    }

    fn finish(&mut self) {
        self.bits_per_second = self.bytes as f64 * 8.0 / self.seconds
    }
}

#[derive(Serialize)]
struct Timestamp {
    #[serde(serialize_with = "serialize_timestamp")]
    timestamp: SystemTime,
}

fn serialize_timestamp<S>(time: &SystemTime, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut state = s.serialize_map(Some(1))?;
    state.serialize_entry(
        "timesecs",
        &time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
    )?;
    state.end()
}

#[derive(Serialize)]
struct Stats {
    /// Test start time
    #[serde(skip)]
    start_instant: Instant,
    /// Test start system time
    start: Timestamp,
    /// Durations of complete requests
    #[serde(skip)]
    duration: Histogram<u64>,
    /// Time from finishing the upload until receiving the first byte of the response
    #[serde(skip)]
    fbl: Histogram<u64>,
    /// Throughput for uploads
    #[serde(skip)]
    upload_throughput: Histogram<u64>,
    /// Throughput for downloads
    #[serde(skip)]
    download_throughput: Histogram<u64>,
    /// The total amount of requests executed
    #[serde(skip)]
    requests: usize,
    /// The amount of successful requests
    #[serde(skip)]
    success: usize,
    /// Stats for each stream
    #[serde(skip)]
    stream_stats: Mutex<Vec<Arc<StreamStats>>>,
    /// Stats accumulated over each interval
    intervals: Vec<Interval>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start_instant: Instant::now(),
            start: Timestamp {
                timestamp: SystemTime::now(),
            },
            duration: Histogram::new(3).unwrap(),
            fbl: Histogram::new(3).unwrap(),
            upload_throughput: Histogram::new(3).unwrap(),
            download_throughput: Histogram::new(3).unwrap(),
            requests: 0,
            success: 0,
            stream_stats: Mutex::new(vec![]),
            intervals: vec![],
        }
    }
}

impl Stats {
    pub fn record(&mut self, request: RequestStats) {
        self.requests += 1;
        self.success += if request.success { 1 } else { 0 };

        // Record the remaining metrics only if the request is successful
        // In this case all timings are available
        if !request.success {
            return;
        }

        let duration = request.download_end.unwrap().duration_since(request.start);
        self.duration.record(duration.as_millis() as u64).unwrap();

        let fbl = request
            .first_byte
            .unwrap()
            .duration_since(request.download_start.unwrap());
        self.fbl.record(fbl.as_millis() as u64).unwrap();

        let download_duration = request
            .download_end
            .unwrap()
            .duration_since(request.download_start.unwrap());
        let download_bps = throughput_bps(download_duration, request.download_size);
        self.download_throughput
            .record(download_bps as u64)
            .unwrap();

        let upload_duration = request
            .download_start
            .unwrap()
            .duration_since(request.upload_start.unwrap());
        let upload_bps = throughput_bps(upload_duration, request.upload_size);
        self.upload_throughput.record(upload_bps as u64).unwrap();
    }

    pub fn print(&self) {
        let dt = self.start_instant.elapsed();
        let rps = self.requests as f64 / dt.as_secs_f64();

        println!("Overall stats:");
        println!(
            "RPS: {:.2} ({} requests in {:4.2?})",
            rps, self.requests, dt,
        );
        println!(
            "Success rate: {:4.2}%",
            100.0 * self.success as f64 / self.requests as f64,
        );
        println!();

        println!("Stream metrics:\n");

        println!("      │ Duration  │ FBL       | Upload Throughput | Download Throughput");
        println!("──────┼───────────┼───────────┼───────────────────┼────────────────────");

        let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
            println!(
                " {} │ {:>9} │ {:>9} │ {:11.2} MiB/s │ {:13.2} MiB/s",
                label,
                format!("{:.2?}", Duration::from_millis(get_metric(&self.duration))),
                format!("{:.2?}", Duration::from_millis(get_metric(&self.fbl))),
                get_metric(&self.upload_throughput) as f64 / 1024.0 / 1024.0,
                get_metric(&self.download_throughput) as f64 / 1024.0 / 1024.0,
            );
        };

        print_metric("AVG ", |hist| hist.mean() as u64);
        print_metric("P0  ", |hist| hist.value_at_quantile(0.00));
        print_metric("P10 ", |hist| hist.value_at_quantile(0.10));
        print_metric("P50 ", |hist| hist.value_at_quantile(0.50));
        print_metric("P90 ", |hist| hist.value_at_quantile(0.90));
        print_metric("P100", |hist| hist.value_at_quantile(1.00));
        println!();
    }

    pub fn report_interval(&mut self, start: Instant) {
        let mut interval = Interval::new(start - self.start_instant, self.start_instant.elapsed());

        let mut guard = self.stream_stats.lock().unwrap();
        guard.retain(|stream_stats| {
            interval.add_stream_stats(stream_stats.clone());

            // Retain if not finished yet
            stream_stats.finished.load(Ordering::Relaxed) == false
        });

        // Calculate throughput over the sum
        interval.recv_stream_sum.finish();
        interval.send_stream_sum.finish();

        self.intervals.push(interval);
    }
}

fn throughput_bps(duration: Duration, size: u64) -> f64 {
    (size as f64) / (duration.as_secs_f64())
}
