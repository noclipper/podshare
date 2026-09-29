//! Sending a pod straight to someone with Magic Wormhole: a short code, a strong key
//! agreed from it (PAKE, so a wrong guess gets one try), no account and no upload.

use anyhow::{bail, Context, Result};
use futures::io::Cursor;
use magic_wormhole::{transfer, transit, AppID, Code, MailboxConnection, Wormhole};
use futures::future::{select, Either};
use std::future::Future;
use std::io::Write;
use std::time::Duration;

/// How long a receiver waits on each step before deciding the sender is gone.
const PATIENCE: Duration = Duration::from_secs(45);

/// `f`, or an error saying `gone` if it takes longer than `PATIENCE`.
async fn within<T>(gone: &str, f: impl Future<Output = T>) -> Result<T> {
    match select(Box::pin(f), async_io::Timer::after(PATIENCE)).await {
        Either::Left((value, _)) => Ok(value),
        Either::Right(_) => bail!("{gone}"),
    }
}

/// podshare's own id on the rendezvous server, so it only ever meets itself.
const APP_ID: &str = "github.com/noclipper/podshare";

fn relay() -> Vec<transit::RelayHint> {
    let url = transit::DEFAULT_RELAY_SERVER.parse().expect("valid relay url");
    vec![transit::RelayHint::from_urls(None, [url]).expect("valid relay hint")]
}

/// Redraws one progress line, at most once per percent.
fn progress(verb: &'static str) -> impl FnMut(u64, u64) + 'static {
    let mut shown = u64::MAX;
    move |done, total| {
        let percent = done * 100 / total.max(1);
        if percent != shown {
            shown = percent;
            print!("\r  {verb} {} / {} ({percent}%)", crate::size(done), crate::size(total));
            let _ = std::io::stdout().flush();
        }
    }
}

/// Waits for the receiver, then hands over the pod's key with a summary of what it holds,
/// and the pod if they accept it.
/// What to say when the relay can't be reached; the underlying error only repeats itself.
const OFFLINE: &str = "can't reach the Magic Wormhole relay; check your internet connection";

pub fn send(file_name: &str, pod: Vec<u8>, key: &str, summary: &serde_json::Value) -> Result<()> {
    async_io::block_on(async {
        let config = transfer::APP_CONFIG.id(AppID::new(APP_ID));
        let mailbox = MailboxConnection::create(config, 2).await.map_err(|_| anyhow::anyhow!("{OFFLINE}"))?;
        println!("  Tell them to run:\n\n    podshare receive {}\n", mailbox.code());
        println!("  Waiting for them to connect (Ctrl-C to cancel)…");
        let mut wormhole = Wormhole::connect(mailbox).await.map_err(|e| friendly(e, false))?;
        wormhole.send_json(&serde_json::json!({ "pod_key": key, "summary": summary })).await?;
        println!("  Connected. Waiting for them to accept…");
        let size = pod.len() as u64;
        let cancel = futures::future::pending::<()>();
        let sent =
            transfer::send_file(wormhole, relay(), &mut Cursor::new(pod), file_name, size, transit::Abilities::ALL, |_| {}, progress("sent"), cancel)
                .await;
        if let Err(e) = sent {
            if e.to_string().to_lowercase().contains("reject") {
                bail!("they declined it; nothing was sent");
            }
            return Err(e).context("the transfer failed");
        }
        println!("\n✓ sent");
        Ok(())
    })
}

/// Connects with the sender's code and returns the pod and its key. Before anything is
/// downloaded, `accept` sees the sender's summary and the pod's size and decides; anything
/// larger than `max` is refused outright.
/// The pod and its key, or `None` if the receiver declined it.
pub fn receive(code: &str, max: u64, accept: impl Fn(&serde_json::Value, u64) -> Result<bool>) -> Result<Option<(Vec<u8>, String)>> {
    let code: Code = code.parse().ok().context("that isn't a podshare code; it looks like 7-crossover-clockwork")?;
    async_io::block_on(async {
        let config = transfer::APP_CONFIG.id(AppID::new(APP_ID));
        let mailbox = MailboxConnection::connect(config, code, false).await.map_err(|e| {
            if e.to_string().to_lowercase().contains("nameplate") {
                anyhow::anyhow!("no one is sending with that code; check it, and that the sender is still waiting")
            } else {
                anyhow::anyhow!("{OFFLINE}")
            }
        })?;
        let gone = "the sender stopped waiting; ask them to run `podshare send` again for a new code";
        let mut wormhole = within(gone, Wormhole::connect(mailbox)).await?.map_err(|e| friendly(e, true))?;
        let hello: serde_json::Value = within(gone, wormhole.receive_json()).await??.context("the sender isn't podshare")?;
        let key = hello["pod_key"].as_str().context("the sender isn't sending a pod")?.to_string();
        let cancel = futures::future::pending::<()>();
        let request = within(gone, transfer::request_file(wormhole, relay(), transit::Abilities::ALL, cancel))
            .await?
            .context("the transfer failed")?
            .context("the sender cancelled")?;
        if request.file_size() > max {
            let size = request.file_size();
            request.reject().await?;
            bail!("the pod is {} MB, more than the {} MB podshare accepts; refused", size >> 20, max >> 20);
        }
        if !accept(&hello["summary"], request.file_size())? {
            request.reject().await?;
            return Ok(None);
        }
        let mut pod = Cursor::new(Vec::new());
        let cancel = futures::future::pending::<()>();
        request.accept(|_| {}, progress("received"), &mut pod, cancel).await.context("the transfer failed")?;
        println!("\n✓ received\n");
        Ok(Some((pod.into_inner(), key)))
    })
}

/// A wrong code shows up as a failed key agreement; say so plainly.
fn friendly(e: magic_wormhole::WormholeError, receiving: bool) -> anyhow::Error {
    let text = e.to_string().to_lowercase();
    if text.contains("pake") || text.contains("key confirmation") {
        anyhow::anyhow!(if receiving {
            "the code didn't match: it was mistyped, or someone else tried it first. \
             Codes work once; ask the sender to run `podshare send` again for a new one"
        } else {
            "the receiver typed a wrong code, or someone else tried it first, so nothing was sent. \
             Run `podshare send` again for a new code"
        })
    } else {
        anyhow::Error::new(e).context("the wormhole connection failed")
    }
}
