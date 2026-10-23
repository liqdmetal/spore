//! spore-iroh — a self-hosted, content-addressed P2P blob carrier for spore.
//!
//! Implements the CLI contract of spore's body-store seam
//! (`internal/store/irohstore.go`):
//!
//!   spore-iroh --version       -> explicit sidecar capability probe
//!   spore-iroh blob add FILE  -> import a body up to 20 MiB; print its hash
//!   spore-iroh blob get HASH  -> emit verified bytes only on stdout
//!   spore-iroh blob serve     -> serve the local store to paired peers
//!   spore-iroh info           -> print this node's provider ticket
//!
//! Env: SPORE_IROH_STORE (user-scoped store root by default),
//!      SPORE_IROH_PROVIDERS (comma-separated provider tickets exchanged out of band),
//!      SPORE_IROH_BIND_ADDR (optional local IP:port; useful for loopback tests).
//!
//! Network posture: the Minimal preset omits the default relay and address-lookup
//! integrations. Operators exchange provider tickets out of band and dial
//! directly; endpoint addresses and timing remain visible to the peer. This mode
//! does not provide NAT traversal. A provider ticket is an address, not an access
//! control token; callers must only serve public data or end-to-end ciphertext.

mod control;

use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use iroh::{Endpoint, EndpointAddr, endpoint::presets, protocol::Router};
use iroh_blobs::{
    BlobFormat, BlobsProtocol, Hash, get::request, store::fs::FsStore, ticket::BlobTicket,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

const VERSION: &str = concat!(
    "spore-iroh ",
    env!("CARGO_PKG_VERSION"),
    "; capabilities=e2-locator-v2,endpoint-minimal; iroh 1.2.0 / iroh-blobs 0.103.0"
);
pub(crate) const MAX_BODY_BYTES: usize = 20 * 1024 * 1024;
const MAX_HASH_ARGUMENT_BYTES: usize = 128;
pub(crate) const MAX_PROVIDER_CONFIG_BYTES: usize = 16 * 1024;
pub(crate) const MAX_PROVIDERS: usize = 8;
pub(crate) const PROVIDER_TIMEOUT_SECS: u64 = 25;
const BIND_TIMEOUT: Duration = Duration::from_secs(10);
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(PROVIDER_TIMEOUT_SECS);

fn usage() {
    println!("spore-iroh — Spore's Iroh blob sidecar");
    println!("usage:");
    println!("  spore-iroh --version");
    println!("  spore-iroh info");
    println!("  spore-iroh blob add <file>");
    println!("  spore-iroh blob get <hash>");
    println!("  spore-iroh blob serve");
    println!("env:");
    println!(
        "  SPORE_IROH_STORE       user-scoped store root (platform data directory by default)"
    );
    println!(
        "  SPORE_IROH_PROVIDERS   comma-separated provider tickets (max 8; exchanged out of band)"
    );
    println!("  SPORE_IROH_BIND_ADDR   optional local IP:port (port 0 selects an ephemeral port)");
    println!(
        "limits: body {} MiB; provider config {} KiB; providers {}; per-provider timeout {}s",
        MAX_BODY_BYTES / (1024 * 1024),
        MAX_PROVIDER_CONFIG_BYTES / 1024,
        MAX_PROVIDERS,
        PROVIDER_TIMEOUT.as_secs()
    );
}

fn default_store_root() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local) = env::var_os("LOCALAPPDATA").filter(|value| !value.is_empty()) {
            return PathBuf::from(local).join("Spore").join("Iroh");
        }
        if let Some(home) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return PathBuf::from(home)
                .join("AppData")
                .join("Local")
                .join("Spore")
                .join("Iroh");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Spore")
                .join("Iroh");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(data) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
            return PathBuf::from(data).join("spore").join("iroh");
        }
        if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("spore")
                .join("iroh");
        }
    }
    PathBuf::from("iroh-data")
}

fn store_root() -> PathBuf {
    env::var_os("SPORE_IROH_STORE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_store_root)
}

fn configured_bind_addr() -> anyhow::Result<Option<SocketAddr>> {
    match env::var("SPORE_IROH_BIND_ADDR") {
        Ok(value) if value.trim().is_empty() => Ok(None),
        Ok(value) => value
            .parse::<SocketAddr>()
            .map(Some)
            .context("SPORE_IROH_BIND_ADDR must be an IP:port socket address"),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("SPORE_IROH_BIND_ADDR must be valid UTF-8"),
    }
}

fn provider_entry(addr: EndpointAddr) -> String {
    // A BlobTicket is the canonical FromStr<->Display form that carries a
    // full EndpointAddr (the "iroh://..." link format): encoding the provider
    // as a ticket with a placeholder hash makes the table round-trip through
    // nothing but the URL parser. The hash is never dialed on.
    let ticket = BlobTicket::new(addr, Hash::new(&[0u8; 32]), BlobFormat::Raw);
    format!("{}", ticket)
}

fn providers_raw() -> anyhow::Result<String> {
    match env::var("SPORE_IROH_PROVIDERS") {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(String::new()),
        Err(env::VarError::NotUnicode(_)) => bail!("SPORE_IROH_PROVIDERS must be valid UTF-8"),
    }
}

pub(crate) fn parse_provider_config(raw: &str) -> anyhow::Result<Vec<EndpointAddr>> {
    if raw.len() > MAX_PROVIDER_CONFIG_BYTES {
        bail!("SPORE_IROH_PROVIDERS exceeds the configuration size limit");
    }
    if raw.contains('\n') || raw.contains('\r') {
        bail!("SPORE_IROH_PROVIDERS contains an invalid line break");
    }

    let mut out = Vec::new();
    for raw_ticket in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if out.len() == MAX_PROVIDERS {
            bail!("SPORE_IROH_PROVIDERS exceeds the provider count limit");
        }
        let ticket = raw_ticket
            .parse::<BlobTicket>()
            .map_err(|_| anyhow!("invalid provider ticket at position {}", out.len() + 1))?;
        out.push(ticket.addr().clone());
    }
    Ok(out)
}

fn providers() -> anyhow::Result<Vec<EndpointAddr>> {
    parse_provider_config(&providers_raw()?)
}

async fn endpoint_new() -> anyhow::Result<Endpoint> {
    let builder = Endpoint::builder(presets::Minimal);
    let builder = match configured_bind_addr()? {
        Some(addr) => builder
            .bind_addr(addr)
            .context("invalid local endpoint bind address")?,
        None => builder,
    };
    timeout(BIND_TIMEOUT, builder.bind())
        .await
        .map_err(|_| anyhow!("Iroh endpoint bind timed out"))?
        .context("could not bind Iroh endpoint")
}

async fn cmd_info() -> anyhow::Result<()> {
    let ep = endpoint_new().await?;
    let ticket = provider_entry(ep.addr());
    println!("endpoint_id {}", ep.id());
    println!("provider_ticket {}", ticket);
    ep.close().await;
    Ok(())
}

async fn cmd_add(file: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(file);
    let metadata = tokio::fs::metadata(&path)
        .await
        .context("could not inspect input file")?;
    if !metadata.is_file() {
        bail!("input must be a regular file");
    }
    if metadata.len() > MAX_BODY_BYTES as u64 {
        bail!(
            "input exceeds the {} MiB body limit",
            MAX_BODY_BYTES / (1024 * 1024)
        );
    }

    // Metadata can become stale while a file is read, so enforce the limit on
    // bytes actually consumed as well as on the initial file size.
    let file = tokio::fs::File::open(&path)
        .await
        .context("could not open input file")?;
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .await
        .context("could not read input file")?;
    if body.len() > MAX_BODY_BYTES {
        bail!(
            "input exceeds the {} MiB body limit",
            MAX_BODY_BYTES / (1024 * 1024)
        );
    }

    let root = store_root();
    let hash = match control::acquire_store_access(&root).await? {
        control::StoreAccess::Local(_lock) => {
            let store = FsStore::load(root)
                .await
                .context("could not open local Iroh store")?;
            let add_result = store.blobs().add_bytes(Bytes::from(body)).await;
            let shutdown_result = store.shutdown().await;
            let tag = add_result.context("could not add blob to local Iroh store")?;
            shutdown_result.context("could not flush local Iroh store")?;
            tag.hash
        }
        control::StoreAccess::Provider(paths) => control::submit_add(&paths, &body).await?,
    };
    println!("{}", hash.to_hex());
    Ok(())
}

pub(crate) async fn fetch_from(
    ep: &Endpoint,
    provider_addrs: &[EndpointAddr],
    hash: Hash,
) -> anyhow::Result<Bytes> {
    if provider_addrs.is_empty() {
        bail!("no provider is configured for this blob");
    }

    let mut failures = Vec::with_capacity(provider_addrs.len());
    for (index, addr) in provider_addrs.iter().cloned().enumerate() {
        let attempt = async {
            let connection = ep
                .connect(addr, iroh_blobs::ALPN)
                .await
                .map_err(|_| anyhow!("connect failed"))?;
            let (declared_size, _) = request::get_verified_size(&connection, &hash)
                .await
                .map_err(|_| anyhow!("size verification failed"))?;
            if declared_size > MAX_BODY_BYTES as u64 {
                bail!("provider blob exceeds the configured body limit");
            }
            let (bytes, _) = request::get_blob(connection, hash)
                .bytes_and_stats()
                .await
                .map_err(|_| anyhow!("blob transfer or Iroh verification failed"))?;
            if bytes.len() as u64 != declared_size {
                bail!("provider blob size did not match its verified size");
            }
            if Hash::new(bytes.as_ref()) != hash {
                bail!("provider blob hash did not match the requested locator");
            }
            Ok::<Bytes, anyhow::Error>(bytes)
        };

        match timeout(PROVIDER_TIMEOUT, attempt).await {
            Ok(Ok(bytes)) => return Ok(bytes),
            Ok(Err(error)) => failures.push(format!("provider {}: {error}", index + 1)),
            Err(_) => failures.push(format!("provider {}: timed out", index + 1)),
        }
    }
    bail!(
        "no configured provider returned a verified blob ({})",
        failures.join("; ")
    )
}

pub(crate) async fn read_local_blob(
    store: &FsStore,
    hash: Hash,
) -> anyhow::Result<Option<Vec<u8>>> {
    if !store.blobs().has(hash).await? {
        return Ok(None);
    }
    let reader = store.blobs().reader(hash);
    let mut bounded_reader = reader.take(MAX_BODY_BYTES as u64 + 1);
    let mut body = Vec::new();
    bounded_reader.read_to_end(&mut body).await?;
    if body.len() > MAX_BODY_BYTES {
        bail!("local blob exceeds the configured body limit");
    }
    if Hash::new(&body) != hash {
        bail!("local blob failed Iroh hash verification");
    }
    Ok(Some(body))
}

async fn cmd_get(hash_str: &str) -> anyhow::Result<()> {
    if hash_str.len() > MAX_HASH_ARGUMENT_BYTES {
        bail!("blob locator exceeds the input size limit");
    }
    let hash: Hash = hash_str.parse().context("invalid Iroh blob locator")?;
    let root = store_root();
    let access = control::acquire_store_access(&root).await?;
    let body = match access {
        control::StoreAccess::Provider(paths) => {
            let raw_providers = providers_raw()?;
            control::submit_get(&paths, hash, &raw_providers).await?
        }
        control::StoreAccess::Local(_lock) => {
            let store = FsStore::load(root)
                .await
                .context("could not open local Iroh store")?;
            let result: anyhow::Result<Vec<u8>> = async {
                if let Some(body) = read_local_blob(&store, hash).await? {
                    return Ok(body);
                }

                let provider_addrs = providers()?;
                if provider_addrs.is_empty() {
                    bail!("blob is not local and no SPORE_IROH_PROVIDERS are configured");
                }
                let ep = endpoint_new().await?;
                let fetch_result = fetch_from(&ep, &provider_addrs, hash).await;
                ep.close().await;
                let bytes = fetch_result?;

                match store.blobs().add_bytes(bytes.clone()).await {
                    Ok(tag) if tag.hash == hash => {}
                    Ok(_) => bail!("cached blob hash did not match the requested locator"),
                    Err(_) => eprintln!(
                        "spore-iroh: verified transfer succeeded but local caching failed"
                    ),
                }
                Ok(bytes.to_vec())
            }
            .await;
            let shutdown_result = store.shutdown().await;
            let body = result?;
            shutdown_result.context("could not flush local Iroh store")?;
            body
        }
    };

    let mut stdout = tokio::io::stdout();
    stdout.write_all(&body).await?;
    stdout.flush().await?;
    Ok(())
}

async fn cmd_serve() -> anyhow::Result<()> {
    let root = store_root();
    let (_store_lock, control_paths) = control::acquire_server_lock(&root).await?;
    let ep = endpoint_new().await?;
    let store = FsStore::load(root)
        .await
        .context("could not open local Iroh store")?;
    let endpoint_id = ep.id();
    let ticket = provider_entry(ep.addr());
    let control_task = tokio::spawn(control::run_control_loop(
        store.clone(),
        ep.clone(),
        control_paths.clone(),
    ));
    let blobs = BlobsProtocol::new(&store, None);
    let router = Router::builder(ep).accept(iroh_blobs::ALPN, blobs).spawn();

    let serve_result: anyhow::Result<()> = async {
        control::mark_ready(&control_paths).await?;
        let mut stdout = tokio::io::stdout();
        let output = format!("endpoint_id: {endpoint_id}\nprovider_ticket: {ticket}\n");
        stdout
            .write_all(output.as_bytes())
            .await
            .context("could not publish provider ticket")?;
        stdout
            .flush()
            .await
            .context("could not flush provider ticket")?;
        tokio::signal::ctrl_c()
            .await
            .context("failed waiting for shutdown signal")?;
        Ok(())
    }
    .await;

    let stopping_result = control::mark_stopping(&control_paths).await;
    let mut control_task = control_task;
    let control_shutdown = match timeout(Duration::from_secs(120), &mut control_task).await {
        Ok(Ok(result)) => result.context("Iroh provider control loop failed"),
        Ok(Err(error)) => Err(anyhow!("Iroh provider control task failed: {error}")),
        Err(_) => {
            control_task.abort();
            Err(anyhow!(
                "Iroh provider control loop did not drain before shutdown"
            ))
        }
    };
    let markers_result = control::clear_markers(&control_paths).await;
    let router_shutdown = router.shutdown().await;
    let store_shutdown = store.shutdown().await;
    serve_result?;
    stopping_result?;
    control_shutdown?;
    markers_result?;
    router_shutdown.context("failed to shut down Iroh provider")?;
    store_shutdown.context("failed to flush local Iroh store")?;
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match arg_refs.as_slice() {
        ["--version"] | ["version"] => println!("{VERSION}"),
        ["--help"] | ["help"] => usage(),
        ["info"] => cmd_info().await?,
        ["blob", "add", file] => cmd_add(file).await?,
        ["blob", "get", hash] => cmd_get(hash).await?,
        ["blob", "serve"] | ["serve"] => cmd_serve().await?,
        _ => {
            usage();
            bail!("unrecognized command");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("spore-iroh: {error:#}");
        std::process::exit(1);
    }
}
