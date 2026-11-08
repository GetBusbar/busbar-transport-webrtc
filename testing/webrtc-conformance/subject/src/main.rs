// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BROWSER CELL'S SUBJECT: busbar's terminating path for a datagram association, answering a
//! headless browser's offer and echoing what it sends.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use busbar_core_connector::datagram::{stream_head, Associations, DatagramFraming, StreamHead};
use busbar_core_connector::framer::{FramerDoor, Got};
use busbar_core_connector::udp::{bind, ReadyPort, MAX_DATAGRAM};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use busbar_core_connector::doors;
use busbar_plugin_loader as loader;

/// The cell's page.
const PAGE: &str = include_str!("../../page/index.html");

/// The largest request the subject reads (an offer is a few kilobytes).
const MAX_REQUEST: usize = 256 * 1024;

/// What the negative control stops echoing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Break {
    None,
    Media,
    Close,
}

/// The `webrtc` door, admitted through the one dispatcher under its row's name and opened.
fn door() -> Arc<dyn FramerDoor> {
    use loader::dispatch::{kinds::transport::Transport as TransportKind, load_linked, LinkedRow};
    let key = "webrtc";
    let plugin = doors::row_bind(key)
        .and_then(|bind| {
            LinkedRow::of(busbar_transport_webrtc::door)
                .and_then(|row| load_linked::<TransportKind>(&row, bind))
                .map_err(|e| e.to_string())
        })
        .unwrap_or_else(|e| panic!("webrtc-conformance-subject: the `{key}` door is refused: {e}"));
    Arc::new(
        doors::Dispatched::open(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
        )
        .unwrap_or_else(|e| {
            panic!("webrtc-conformance-subject: the `{key}` door would not open: {e}")
        }),
    )
}

/// The associations on the port, and what each stream of each one is.
struct Port {
    port: ReadyPort,
    assocs: Associations,
    /// `(association, stream)` -> the stream is a line (else a channel).
    lines: HashMap<(u64, u64), bool>,
    broken: Break,
    closed_channels: HashSet<u64>,
}

impl Port {
    fn flush(&mut self) {
        while let Some((to, d)) = self.assocs.poll_send() {
            let _ = self.port.send_to(&d, to);
        }
    }

    /// Echo what association `id` yielded.
    fn echo(&mut self, id: u64, pieces: Vec<Got>, now: Instant) {
        for g in pieces {
            if g.end {
                self.lines.remove(&(id, g.stream));
                if self.broken != Break::Close {
                    self.closed_channels.insert(id);
                }
                continue;
            }
            if g.fields {
                let line = matches!(stream_head(&g.bytes), Some(StreamHead::Line { .. }));
                self.lines.insert((id, g.stream), line);
                continue;
            }
            if g.stream == 0 || g.bytes.is_empty() {
                continue;
            }
            let line = self.lines.get(&(id, g.stream)).copied().unwrap_or(false);
            let skip = match self.broken {
                Break::None | Break::Close => false,
                Break::Media => line,
            };
            if skip {
                continue;
            }
            if let Some(f) = self.assocs.get_mut(id) {
                if let Err(e) = f.emit(g.stream, &g.bytes, g.end_of_frame, g.text, now) {
                    eprintln!(
                        "webrtc-conformance-subject: association {id} refused an echo on stream {}: {e}",
                        g.stream
                    );
                }
            }
        }
        self.flush();
    }
}

/// The port's task: every datagram to its association, the clock kept, everything echoed.
async fn serve_port(port: Rc<RefCell<Port>>) {
    let mut buf = vec![0_u8; MAX_DATAGRAM];
    loop {
        let deadline = port.borrow().assocs.deadline();
        let read = std::future::poll_fn(|cx| {
            port.borrow()
                .port
                .poll_recv_from(cx, &mut buf)
                .map(|r| r.map(|(n, from)| (buf[..n].to_vec(), from)))
        });
        let sleep = async {
            match deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        };
        let got = tokio::select! {
            got = read => Some(got),
            () = sleep => None,
        };
        let now = Instant::now();
        let answered = {
            let mut p = port.borrow_mut();
            match got {
                Some(Ok((d, from))) => p.assocs.datagram(from, &d, now).into_iter().collect(),
                Some(Err(_)) => Vec::new(),
                None => p.assocs.timeout(now),
            }
        };
        let mut p = port.borrow_mut();
        for (id, answer) in answered {
            match answer {
                Ok(mut y) => p.echo(id, std::mem::take(&mut y.pieces), now),
                Err(e) => eprintln!("webrtc-conformance-subject: association {id} failed: {e}"),
            }
        }
        p.flush();
    }
}

/// One HTTP request, read whole: its method, path and body.
async fn request(s: &mut tokio::net::TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    let head_end = loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > MAX_REQUEST {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, path) = (first.next()?.to_owned(), first.next()?.to_owned());
    let length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_REQUEST);
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Some((method, path, body))
}

async fn respond(
    s: &mut tokio::net::TcpStream,
    status: &str,
    kind: &str,
    body: &[u8],
    location: Option<&str>,
) {
    let location = location.map_or_else(String::new, |value| format!("location: {value}\r\n"));
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\n{location}connection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(body).await;
    let _ = s.shutdown().await;
}

/// `POST /offer`: the accepting association, settled by the browser's offer, joins the port; the
/// answer is the framer's own description.
fn answer(
    port: &Rc<RefCell<Port>>,
    framer: &Arc<dyn FramerDoor>,
    offer: &[u8],
) -> Result<(Vec<u8>, u64), String> {
    let cert =
        Arc::new(busbar_core_connector::dtls::SessionCert::mint().map_err(|e| format!("{e:?}"))?);
    let local = port.borrow().port.local_addr();
    let (mut f, _) =
        DatagramFraming::accept(Arc::clone(framer), cert, local).map_err(|r| r.error)?;
    let now = Instant::now();
    let mut y = f.rendezvous(offer, now).map_err(|r| r.error)?;
    let description = y
        .pieces
        .iter()
        .find(|g| g.stream == 0 && !g.fields)
        .map(|g| g.bytes.clone())
        .ok_or("the framer answered no description")?;
    let mut p = port.borrow_mut();
    let id = p.assocs.add(f).map_err(|e| format!("{e:?}"))?;
    p.echo(id, std::mem::take(&mut y.pieces), now);
    Ok((description, id))
}

fn main() {
    let broken = match std::env::args()
        .skip_while(|a| a != "--break")
        .nth(1)
        .as_deref()
    {
        Some("media") => Break::Media,
        Some("close") => Break::Close,
        _ => Break::None,
    };
    let host = std::env::var("WEBRTC_SUBJECT_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());

    let worker = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("webrtc-conformance-subject: no runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&worker, async move {
        let framer = door();
        let udp = bind(&format!("{host}:0"))
            .and_then(ReadyPort::open)
            .expect("webrtc-conformance-subject: the datagram port would not bind");
        let port = Rc::new(RefCell::new(Port {
            port: udp,
            assocs: Associations::new(),
            lines: HashMap::new(),
            broken,
            closed_channels: HashSet::new(),
        }));
        tokio::task::spawn_local(serve_port(Rc::clone(&port)));
        let http = tokio::net::TcpListener::bind(format!("{host}:0"))
            .await
            .expect("webrtc-conformance-subject: the page listener would not bind");
        let at: SocketAddr = http.local_addr().expect("the page listener's address");
        println!("WEBRTC_SUBJECT_URL=http://{at}/");
        use std::io::Write as _;
        std::io::stdout().flush().ok();
        loop {
            let Ok((mut s, _)) = http.accept().await else {
                continue;
            };
            let port = Rc::clone(&port);
            let framer = Arc::clone(&framer);
            tokio::task::spawn_local(async move {
                match request(&mut s).await {
                    Some((m, p, _)) if m == "GET" && (p == "/" || p == "/index.html") => {
                        respond(
                            &mut s,
                            "200 OK",
                            "text/html; charset=utf-8",
                            PAGE.as_bytes(),
                            None,
                        )
                        .await;
                    }
                    Some((m, p, body)) if m == "POST" && p == "/offer" => {
                        match answer(&port, &framer, &body) {
                            Ok((d, id)) => {
                                respond(
                                    &mut s,
                                    "201 Created",
                                    "application/sdp",
                                    &d,
                                    Some(&format!("/closed/{id}")),
                                )
                                .await
                            }
                            Err(why) => {
                                respond(
                                    &mut s,
                                    "400 Bad Request",
                                    "text/plain",
                                    why.as_bytes(),
                                    None,
                                )
                                .await
                            }
                        }
                    }
                    Some((m, p, _)) if m == "GET" && p.starts_with("/closed/") => {
                        let closed = p
                            .strip_prefix("/closed/")
                            .and_then(|id| id.parse::<u64>().ok())
                            .is_some_and(|id| port.borrow_mut().closed_channels.remove(&id));
                        respond(
                            &mut s,
                            if closed { "200 OK" } else { "409 Conflict" },
                            "text/plain",
                            b"",
                            None,
                        )
                        .await;
                    }
                    Some(_) => respond(&mut s, "404 Not Found", "text/plain", b"", None).await,
                    None => {}
                }
            });
        }
    });
}
