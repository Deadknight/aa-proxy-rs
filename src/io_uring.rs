use bytesize::ByteSize;
use humantime::format_duration;
use simplelog::*;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_uring::buf::BoundedBuf;
use tokio_uring::buf::BoundedBufMut;
use tokio_uring::fs::File;
use tokio_uring::fs::OpenOptions;
use tokio_uring::net::TcpListener;
use tokio_uring::net::TcpStream;
use tokio_uring::BufResult;
use tokio_uring::UnsubmittedWrite;

// module name for logging engine
const NAME: &str = "<i><bright-black> proxy: </>";

// Just a generic Result type to ease error handling for us. Errors in multithreaded
// async contexts needs some extra restrictions
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const USB_ACCESSORY_PATH: &str = "/dev/usb_accessory";
pub const BUFFER_LEN: usize = 16 * 1024;
const TCP_CLIENT_TIMEOUT: Duration = Duration::new(30, 0);

use crate::mitm::endpoint_reader;
use crate::mitm::proxy;
use crate::mitm::Packet;
use crate::mitm::ProxyType;
use crate::usb_stream;
use crate::usb_stream::{UsbStreamRead, UsbStreamWrite};
use crate::HexdumpLevel;
use crate::{TCP_DHU_PORT, TCP_SERVER_PORT};

// tokio_uring::fs::File and tokio_uring::net::TcpStream are using different
// read and write calls:
// File is using read_at() and write_at(),
// TcpStream is using read() and write()
//
// In our case we are reading a special unix character device for
// the USB gadget, which is not a regular file where an offset is important.
// We just use offset 0 for reading and writing, so below is a trait
// for this, to be able to use it in a generic copy() function below.

pub trait Endpoint<E> {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T>;
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T>;
}

impl Endpoint<File> for File {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read_at(buf, 0).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write_at(buf, 0)
    }
}

impl Endpoint<TcpStream> for TcpStream {
    async fn read<T: BoundedBufMut>(&self, buf: T) -> BufResult<usize, T> {
        self.read(buf).await
    }
    fn write<T: BoundedBuf>(&self, buf: T) -> UnsubmittedWrite<T> {
        self.write(buf)
    }
}

pub enum IoDevice<A: Endpoint<A>> {
    UsbReader(Rc<RefCell<UsbStreamRead>>, PhantomData<A>),
    UsbWriter(Rc<RefCell<UsbStreamWrite>>, PhantomData<A>),
    EndpointIo(Rc<A>),
    TcpStreamIo(Rc<TcpStream>),
}

async fn transfer_monitor(
    stats_interval: Option<Duration>,
    usb_bytes_written: Arc<AtomicUsize>,
    tcp_bytes_written: Arc<AtomicUsize>,
    read_timeout: Duration,
) -> Result<()> {
    let mut usb_bytes_out_last: usize = 0;
    let mut tcp_bytes_out_last: usize = 0;
    let mut stall_usb_bytes_last: usize = 0;
    let mut stall_tcp_bytes_last: usize = 0;
    let mut report_time = Instant::now();
    let mut stall_check = Instant::now();

    loop {
        // load current total transfer from AtomicUsize:
        let usb_bytes_out = usb_bytes_written.load(Ordering::Relaxed);
        let tcp_bytes_out = tcp_bytes_written.load(Ordering::Relaxed);

        // Stats printing
        if stats_interval.is_some() && report_time.elapsed() > stats_interval.unwrap() {
            // compute USB transfer
            usb_bytes_out_last = usb_bytes_out - usb_bytes_out_last;
            let usb_transferred_total = ByteSize::b(usb_bytes_out.try_into().unwrap());
            let usb_transferred_last = ByteSize::b(usb_bytes_out_last.try_into().unwrap());
            let usb_speed: u64 =
                (usb_bytes_out_last as f64 / report_time.elapsed().as_secs_f64()).round() as u64;
            let usb_speed = ByteSize::b(usb_speed);

            // compute TCP transfer
            tcp_bytes_out_last = tcp_bytes_out - tcp_bytes_out_last;
            let tcp_transferred_total = ByteSize::b(tcp_bytes_out.try_into().unwrap());
            let tcp_transferred_last = ByteSize::b(tcp_bytes_out_last.try_into().unwrap());
            let tcp_speed: u64 =
                (tcp_bytes_out_last as f64 / report_time.elapsed().as_secs_f64()).round() as u64;
            let tcp_speed = ByteSize::b(tcp_speed);

            info!(
                "{} {} {: >9} ({: >9}/s), {: >9} total | {} {: >9} ({: >9}/s), {: >9} total",
                NAME,
                "phone -> car 🔺",
                usb_transferred_last.to_string_as(true),
                usb_speed.to_string_as(true),
                usb_transferred_total.to_string_as(true),
                "car -> phone 🔻",
                tcp_transferred_last.to_string_as(true),
                tcp_speed.to_string_as(true),
                tcp_transferred_total.to_string_as(true),
            );

            // save values for next iteration
            report_time = Instant::now();
            usb_bytes_out_last = usb_bytes_out;
            tcp_bytes_out_last = tcp_bytes_out;
        }

        // transfer stall detection
        if stall_check.elapsed() > read_timeout {
            // compute delta since last check
            stall_usb_bytes_last = usb_bytes_out - stall_usb_bytes_last;
            stall_tcp_bytes_last = tcp_bytes_out - stall_tcp_bytes_last;

            if stall_usb_bytes_last == 0 || stall_tcp_bytes_last == 0 {
                return Err("unexpected transfer stall".into());
            }

            // save values for next iteration
            stall_check = Instant::now();
            stall_usb_bytes_last = usb_bytes_out;
            stall_tcp_bytes_last = tcp_bytes_out;
        }

        sleep(Duration::from_millis(100)).await;
    }
}

async fn flatten<T>(handle: &mut JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(_) => Err("handling failed".into()),
    }
}

/// Asynchronously wait for an inbound TCP connection
/// returning TcpStream of first client connected
async fn tcp_wait_for_connection(listener: &mut TcpListener) -> Result<TcpStream> {
    let retval = listener.accept();
    let (stream, addr) = match timeout(TCP_CLIENT_TIMEOUT, retval)
        .await
        .map_err(|e| std::io::Error::other(e))
    {
        Ok(Ok((stream, addr))) => (stream, addr),
        Err(e) | Ok(Err(e)) => {
            error!("{} 📵 TCP server: {}, restarting...", NAME, e);
            return Err(Box::new(e));
        }
    };
    info!(
        "{} 📳 TCP server: new client connected: <b>{:?}</b>",
        NAME, addr
    );
    // disable Nagle algorithm, so segments are always sent as soon as possible,
    // even if there is only a small amount of data
    stream.set_nodelay(true)?;

    Ok(stream)
}

pub async fn io_loop(
    stats_interval: Option<Duration>,
    need_restart: Arc<Notify>,
    tcp_start: Arc<Notify>,
    read_timeout: Duration,
    mitm: bool,
    dpi: Option<u16>,
    developer_mode: bool,
    disable_media_sink: bool,
    disable_tts_sink: bool,
    remove_tap_restriction: bool,
    video_in_motion: bool,
    hex_requested: HexdumpLevel,
    wired: bool,
    dhu: bool,
) -> Result<()> {
    // prepare/bind needed TCP listeners
    let mut dhu_listener = None;
    let mut md_listener = None;
    if !wired {
        info!("{} 🛰️ Starting TCP server for MD...", NAME);
        let bind_addr = format!("0.0.0.0:{}", TCP_SERVER_PORT).parse().unwrap();
        md_listener = Some(TcpListener::bind(bind_addr).unwrap());
        info!("{} 🛰️ MD TCP server bound to: <u>{}</u>", NAME, bind_addr);
    }
    if dhu {
        info!("{} 🛰️ Starting TCP server for DHU...", NAME);
        let bind_addr = format!("0.0.0.0:{}", TCP_DHU_PORT).parse().unwrap();
        dhu_listener = Some(TcpListener::bind(bind_addr).unwrap());
        info!("{} 🛰️ DHU TCP server bound to: <u>{}</u>", NAME, bind_addr);
    }

    loop {
        let mut md_tcp = None;
        let mut md_usb = None;
        let mut hu_tcp = None;
        let mut hu_usb = None;
        if wired {
            info!(
                "{} 💤 trying to enable Android Auto mode on USB port...",
                NAME
            );
            match usb_stream::new().await {
                Err(e) => {
                    error!("{} 🔴 Enabling Android Auto: {}", NAME, e);
                    // notify main loop to restart
                    need_restart.notify_one();
                    continue;
                }
                Ok(s) => {
                    md_usb = Some(s);
                }
            }
        } else {
            info!("{} 💤 waiting for bluetooth handshake...", NAME);
            tcp_start.notified().await;

            info!(
                "{} 🛰️ MD TCP server: listening for phone connection...",
                NAME
            );
            if let Ok(s) = tcp_wait_for_connection(&mut md_listener.as_mut().unwrap()).await {
                md_tcp = Some(s);
            } else {
                // notify main loop to restart
                need_restart.notify_one();
                continue;
            }
        }

        if dhu {
            info!(
                "{} 🛰️ DHU TCP server: listening for `Desktop Head Unit` connection...",
                NAME
            );
            if let Ok(s) = tcp_wait_for_connection(&mut dhu_listener.as_mut().unwrap()).await {
                hu_tcp = Some(s);
            } else {
                // notify main loop to restart
                need_restart.notify_one();
                continue;
            }
        } else {
            info!(
                "{} 📂 Opening USB accessory device: <u>{}</u>",
                NAME, USB_ACCESSORY_PATH
            );
            hu_usb = Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(false)
                    .open(USB_ACCESSORY_PATH)
                    .await?,
            );
        }

        info!("{} ♾️ Starting to proxy data between HU and MD...", NAME);
        let started = Instant::now();

        // `read` and `write` take owned buffers (more on that later), and
        // there's no "per-socket" buffer, so they actually take `&self`.
        // which means we don't need to split them into a read half and a
        // write half like we'd normally do with "regular tokio". Instead,
        // we can send a reference-counted version of it. also, since a
        // tokio-uring runtime is single-threaded, we can use `Rc` instead of
        // `Arc`.
        let file_bytes = Arc::new(AtomicUsize::new(0));
        let stream_bytes = Arc::new(AtomicUsize::new(0));

        let mut from_file;
        let mut from_stream;
        let mut reader_hu;
        let mut reader_md;

        // MITM/proxy mpsc channels:
        let (tx_hu, rx_md): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(10);
        let (tx_md, rx_hu): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(10);
        let (txr_hu, rxr_md): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(10);
        let (txr_md, rxr_hu): (Sender<Packet>, Receiver<Packet>) = mpsc::channel(10);

        // selecting I/O device for reading and writing
        // and creating desired objects for proxy functions
        let hu_r;
        let md_r;
        let hu_w;
        let md_w;
        // MD transfer device
        if let Some(md) = md_usb {
            // MD over wired USB
            let (usb_r, usb_w) = md;
            let usb_r = Rc::new(RefCell::new(usb_r));
            let usb_w = Rc::new(RefCell::new(usb_w));
            md_r = IoDevice::UsbReader(usb_r, PhantomData::<TcpStream>);
            md_w = IoDevice::UsbWriter(usb_w, PhantomData::<TcpStream>);
        } else {
            // MD using TCP stream (wireless)
            let md = Rc::new(md_tcp.unwrap());
            md_r = IoDevice::EndpointIo(md.clone());
            md_w = IoDevice::EndpointIo(md.clone());
        }
        // HU transfer device
        if let Some(hu) = hu_usb {
            // HU connected directly via USB
            let hu = Rc::new(hu);
            hu_r = IoDevice::EndpointIo(hu.clone());
            hu_w = IoDevice::EndpointIo(hu.clone());
        } else {
            // Head Unit Emulator via TCP
            let hu = Rc::new(hu_tcp.unwrap());
            hu_r = IoDevice::TcpStreamIo(hu.clone());
            hu_w = IoDevice::TcpStreamIo(hu.clone());
        }

        // dedicated reading threads:
        reader_hu = tokio_uring::spawn(endpoint_reader(hu_r, txr_hu));
        reader_md = tokio_uring::spawn(endpoint_reader(md_r, txr_md));
        // main processing threads:
        from_file = tokio_uring::spawn(proxy(
            ProxyType::HeadUnit,
            hu_w,
            stream_bytes.clone(),
            tx_hu,
            rx_hu,
            rxr_md,
            dpi,
            developer_mode,
            disable_media_sink,
            disable_tts_sink,
            remove_tap_restriction,
            video_in_motion,
            !mitm,
            hex_requested,
        ));
        from_stream = tokio_uring::spawn(proxy(
            ProxyType::MobileDevice,
            md_w,
            file_bytes.clone(),
            tx_md,
            rx_md,
            rxr_hu,
            dpi,
            developer_mode,
            disable_media_sink,
            disable_tts_sink,
            remove_tap_restriction,
            video_in_motion,
            !mitm,
            hex_requested,
        ));

        // Thread for monitoring transfer
        let mut monitor = tokio::spawn(transfer_monitor(
            stats_interval,
            file_bytes,
            stream_bytes,
            read_timeout,
        ));

        // Stop as soon as one of them errors
        let res = tokio::try_join!(
            flatten(&mut reader_hu),
            flatten(&mut reader_md),
            flatten(&mut from_file),
            flatten(&mut from_stream),
            flatten(&mut monitor)
        );
        if let Err(e) = res {
            error!("{} 🔴 Connection error: {}", NAME, e);
        }
        // Make sure the reference count drops to zero and the socket is
        // freed by aborting both tasks (which both hold a `Rc<TcpStream>`
        // for each direction)
        reader_hu.abort();
        reader_md.abort();
        from_file.abort();
        from_stream.abort();
        monitor.abort();

        info!(
            "{} ⌛ session time: {}",
            NAME,
            format_duration(started.elapsed()).to_string()
        );
        // stream(s) closed, notify main loop to restart
        need_restart.notify_one();
    }
}
