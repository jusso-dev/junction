//! Browser sign-in (authorization code with PKCE) for operator-owned Entra
//! public-client applications. A one-shot listener on the loopback interface
//! receives the redirect; register `http://localhost` as a public-client
//! (mobile and desktop) redirect URI on the application.
use anyhow::{Result, bail};
use junction_auth::{AccessToken, TokenRequest, pkce::PkceProvider, refresh::RefreshCredential};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_REQUEST: usize = 16 * 1024;

/// The request target (`/path?query`) of an HTTP/1.x request line.
pub fn request_target(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    (method == "GET" && version.starts_with("HTTP/1.") && target.starts_with('/'))
        .then(|| target.to_owned())
}

fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let command = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "windows")]
    let command = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .status();
    #[cfg(all(unix, not(target_os = "macos")))]
    let command = std::process::Command::new("xdg-open").arg(url).status();
    command.is_ok_and(|status| status.success())
}

pub async fn login(
    request: &TokenRequest,
    client_id: &str,
    timeout: Duration,
    launch_browser: bool,
) -> Result<(AccessToken, Option<RefreshCredential>)> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|_| anyhow::anyhow!("could not open a local sign-in listener"))?;
    let port = listener.local_addr()?.port();
    let redirect = format!("http://localhost:{port}/");
    let provider = PkceProvider::new(client_id.to_owned(), &redirect)?;
    let mut session = provider.begin(request)?;
    let url = session.authorization_url().to_string();
    if !(launch_browser && open_browser(&url)) {
        eprintln!("Open this address in a browser to sign in:\n{url}");
    } else {
        eprintln!("Continue sign-in in your browser. If it did not open, visit:\n{url}");
    }
    let wait = async {
        loop {
            let (mut stream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let mut head = Vec::new();
            let mut buffer = [0u8; 2048];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
                    .await
                    .map_err(|_| anyhow::anyhow!("sign-in redirect timed out"))??;
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buffer[..read]);
                if head.len() > MAX_REQUEST {
                    bail!("sign-in redirect too large");
                }
            }
            let target = request_target(&head);
            let callback = target.filter(|target| target == "/" || target.starts_with("/?"));
            let Some(callback) = callback else {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                continue;
            };
            let body = "<!doctype html><title>Junction</title><p>Sign-in received. You can close this window and return to the terminal.</p>";
            let _ = stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await;
            let callback = format!("http://localhost:{port}{callback}");
            let token = provider.exchange(&mut session, &callback).await?;
            return Ok::<_, anyhow::Error>((token, session.take_refresh_credential()));
        }
    };
    tokio::select! {
        result = tokio::time::timeout(timeout, wait) => {
            result.map_err(|_| anyhow::anyhow!("interactive login timed out"))?
        }
        _ = tokio::signal::ctrl_c() => bail!("interactive login cancelled"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_get_request_targets_are_accepted() {
        assert_eq!(
            super::request_target(b"GET /?code=a&state=b HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_deref(),
            Some("/?code=a&state=b")
        );
        for head in [
            &b"POST /?code=a HTTP/1.1\r\n\r\n"[..],
            b"GET http://evil/ HTTP/1.1\r\n\r\n",
            b"GET / SMTP\r\n\r\n",
            b"\xff\xfe",
        ] {
            assert!(super::request_target(head).is_none());
        }
    }
}
