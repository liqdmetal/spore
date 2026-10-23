use std::{
    collections::{HashMap, HashSet},
    fs::{OpenOptions, TryLockError},
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use iroh::Endpoint;
use iroh_blobs::{Hash, store::fs::FsStore};
use tokio::{io::AsyncReadExt, task::JoinSet, time::sleep};

use crate::{
    MAX_BODY_BYTES, MAX_PROVIDER_CONFIG_BYTES, fetch_from, parse_provider_config, read_local_blob,
};

const LOCK_FILE: &str = ".spore-iroh.lock";
const CONTROL_DIR: &str = ".spore-iroh-control";
const QUEUE_LOCK_FILE: &str = ".queue.lock";
const READY_FILE: &str = "ready";
const STOPPING_FILE: &str = "stopping";
const REQUEST_WAIT: Duration = Duration::from_secs(20);
const ADD_WAIT: Duration = Duration::from_secs(25);
// Eight serial provider attempts at 25 seconds each, plus a 20-second margin.
const GET_WAIT: Duration =
    Duration::from_secs(crate::MAX_PROVIDERS as u64 * crate::PROVIDER_TIMEOUT_SECS + 20);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_QUEUED_REQUESTS: usize = 8;
const MAX_ACTIVE_REQUESTS: usize = MAX_QUEUED_REQUESTS;
const MAX_QUEUED_BODY_BYTES: u64 = 4 * MAX_BODY_BYTES as u64;
const RESPONSE_TTL: Duration = Duration::from_secs(10 * 60);
const RESPONSE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_REQUEST_FILE_BYTES: usize = MAX_PROVIDER_CONFIG_BYTES + 256;
const MAX_RESPONSE_FILE_BYTES: usize = 2 * 1024;
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct ControlPaths {
    control: PathBuf,
    queue_lock: PathBuf,
    requests: PathBuf,
    responses: PathBuf,
    ready: PathBuf,
    stopping: PathBuf,
}

impl ControlPaths {
    fn new(root: &Path) -> Self {
        let control = root.join(CONTROL_DIR);
        Self {
            queue_lock: control.join(QUEUE_LOCK_FILE),
            requests: control.join("requests"),
            responses: control.join("responses"),
            ready: control.join(READY_FILE),
            stopping: control.join(STOPPING_FILE),
            control,
        }
    }
}

struct QueueLock {
    _file: std::fs::File,
}

pub struct StoreLock {
    // The OS releases this exclusive lock when the handle is dropped or the
    // process exits; a stale lock file is therefore safe to reopen.
    _file: std::fs::File,
}

pub enum StoreAccess {
    Local(StoreLock),
    Provider(ControlPaths),
}

fn open_private_lock(path: &Path) -> anyhow::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("could not open Iroh control lock at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!("could not restrict Iroh control lock at {}", path.display())
            })?;
    }
    Ok(file)
}

fn try_file_lock(path: &Path, description: &str) -> anyhow::Result<Option<std::fs::File>> {
    let file = open_private_lock(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("could not lock {description}"))
        }
    }
}

fn try_lock(root: &Path) -> anyhow::Result<Option<StoreLock>> {
    let path = root.join(LOCK_FILE);
    Ok(try_file_lock(&path, "Iroh store")?.map(|file| StoreLock { _file: file }))
}

fn try_queue_lock(paths: &ControlPaths) -> anyhow::Result<Option<QueueLock>> {
    Ok(try_file_lock(&paths.queue_lock, "Iroh request queue")?
        .map(|file| QueueLock { _file: file }))
}

async fn acquire_queue_lock(paths: &ControlPaths) -> anyhow::Result<QueueLock> {
    let deadline = tokio::time::Instant::now() + REQUEST_WAIT;
    loop {
        if let Some(lock) = try_queue_lock(paths)? {
            return Ok(lock);
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting to reserve Iroh provider queue capacity")
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn create_private_dir(path: &Path, context: &str) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(path)
        .await
        .with_context(|| format!("could not create {context}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| format!("could not restrict {context} permissions"))?;
    }
    Ok(())
}

async fn ensure_control_dirs(paths: &ControlPaths) -> anyhow::Result<()> {
    create_private_dir(&paths.control, "Iroh control directory").await?;
    create_private_dir(&paths.requests, "Iroh control request directory").await?;
    create_private_dir(&paths.responses, "Iroh control response directory").await?;
    Ok(())
}

async fn remove_if_exists(path: &Path) -> anyhow::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("could not remove {}", path.display())),
    }
}

async fn clear_dir(path: &Path) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(path)
        .await
        .with_context(|| format!("could not read {}", path.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        let kind = entry.file_type().await?;
        if kind.is_dir() {
            tokio::fs::remove_dir_all(&entry_path).await?;
        } else {
            tokio::fs::remove_file(&entry_path).await?;
        }
    }
    Ok(())
}

async fn clear_stale_state(paths: &ControlPaths) -> anyhow::Result<()> {
    remove_if_exists(&paths.ready).await?;
    remove_if_exists(&paths.stopping).await?;
    clear_dir(&paths.requests).await?;
    clear_dir(&paths.responses).await?;
    Ok(())
}

pub async fn acquire_store_access(root: &Path) -> anyhow::Result<StoreAccess> {
    create_private_dir(root, "Iroh store root").await?;
    let paths = ControlPaths::new(root);
    ensure_control_dirs(&paths).await?;
    let deadline = tokio::time::Instant::now() + REQUEST_WAIT;

    loop {
        if let Some(lock) = try_lock(root)? {
            clear_stale_state(&paths).await?;
            return Ok(StoreAccess::Local(lock));
        }

        if tokio::fs::try_exists(&paths.ready).await.unwrap_or(false)
            && !tokio::fs::try_exists(&paths.stopping)
                .await
                .unwrap_or(false)
        {
            // Let a just-acquired one-shot lock holder remove a stale ready
            // marker before routing this request to the long-lived provider.
            sleep(POLL_INTERVAL * 2).await;
            if tokio::fs::try_exists(&paths.ready).await.unwrap_or(false)
                && !tokio::fs::try_exists(&paths.stopping)
                    .await
                    .unwrap_or(false)
                && try_lock(root)?.is_none()
            {
                return Ok(StoreAccess::Provider(paths));
            }
            continue;
        }

        if tokio::time::Instant::now() >= deadline {
            bail!("Iroh store is busy; provider startup or another local operation did not finish")
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub async fn acquire_server_lock(root: &Path) -> anyhow::Result<(StoreLock, ControlPaths)> {
    create_private_dir(root, "Iroh store root").await?;
    let paths = ControlPaths::new(root);
    ensure_control_dirs(&paths).await?;
    let deadline = tokio::time::Instant::now() + REQUEST_WAIT;

    loop {
        if let Some(lock) = try_lock(root)? {
            clear_stale_state(&paths).await?;
            return Ok((lock, paths));
        }
        if tokio::fs::try_exists(&paths.ready).await.unwrap_or(false)
            && !tokio::fs::try_exists(&paths.stopping)
                .await
                .unwrap_or(false)
        {
            bail!("an Iroh provider is already serving this store")
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("Iroh store is busy; could not acquire its exclusive provider lock")
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub async fn mark_ready(paths: &ControlPaths) -> anyhow::Result<()> {
    tokio::fs::write(&paths.ready, b"spore-iroh-control-v1\n")
        .await
        .context("could not publish Iroh provider control endpoint")
}

pub async fn mark_stopping(paths: &ControlPaths) -> anyhow::Result<()> {
    tokio::fs::write(&paths.stopping, b"stopping\n")
        .await
        .context("could not mark Iroh provider as stopping")
}

pub async fn clear_markers(paths: &ControlPaths) -> anyhow::Result<()> {
    remove_if_exists(&paths.ready).await?;
    remove_if_exists(&paths.stopping).await?;
    Ok(())
}

fn new_id() -> String {
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}-{:x}", process::id(), ticks, sequence)
}

fn file_for(dir: &Path, id: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{id}.{suffix}"))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let temp = path.with_file_name(format!(".tmp-{}", new_id()));
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .await
        .with_context(|| format!("could not create control file {}", temp.display()))?;
    let write_result = async {
        file.write_all(bytes).await?;
        file.flush().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    drop(file);
    if let Err(error) = write_result {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(error)
            .with_context(|| format!("could not write control file {}", temp.display()));
    }
    if let Err(error) = tokio::fs::rename(&temp, path).await {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(error)
            .with_context(|| format!("could not publish control file {}", path.display()));
    }
    Ok(())
}

#[derive(Default)]
struct QueueItem {
    request: bool,
    response: bool,
    payload: bool,
    body: bool,
    body_bytes: u64,
}

async fn check_queue_capacity(paths: &ControlPaths, additional_bytes: u64) -> anyhow::Result<()> {
    let mut items: HashMap<String, QueueItem> = HashMap::new();
    let mut requests = 0usize;
    let mut body_bytes = 0u64;
    for directory in [&paths.requests, &paths.responses] {
        let mut entries = tokio::fs::read_dir(directory).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file() {
                continue;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if name.starts_with(".tmp-") {
                requests += 1;
                body_bytes = body_bytes.saturating_add(entry.metadata().await?.len());
                continue;
            }
            let (id, suffix) = match name.rsplit_once('.') {
                Some(parts) => parts,
                None => continue,
            };
            let item = items.entry(id.to_owned()).or_default();
            match suffix {
                "req" => item.request = true,
                "resp" => item.response = true,
                "payload" => {
                    item.payload = true;
                    item.body_bytes = item
                        .body_bytes
                        .saturating_add(entry.metadata().await?.len());
                }
                "body" => {
                    item.body = true;
                    item.body_bytes = item
                        .body_bytes
                        .saturating_add(entry.metadata().await?.len());
                }
                _ => continue,
            }
        }
    }
    for item in items.values() {
        requests += 1;
        body_bytes = body_bytes.saturating_add(item.body_bytes);
        // A queued GET can produce a full-size response even before the body
        // file exists. Reserve that maximum until a response is published.
        if item.request && !item.response && !item.payload && !item.body {
            body_bytes = body_bytes.saturating_add(MAX_BODY_BYTES as u64);
        }
    }
    if requests >= MAX_QUEUED_REQUESTS
        || body_bytes.saturating_add(additional_bytes) > MAX_QUEUED_BODY_BYTES
    {
        bail!("Iroh provider request queue is full; retry after it drains")
    }
    Ok(())
}

async fn wait_response(paths: &ControlPaths, id: &str, wait: Duration) -> anyhow::Result<Vec<u8>> {
    let response_path = file_for(&paths.responses, id, "resp");
    let result = tokio::time::timeout(wait, async {
        loop {
            if let Some(response) =
                read_bounded_if_exists(&response_path, MAX_RESPONSE_FILE_BYTES).await?
            {
                return Ok(response);
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    match result {
        Ok(response) => response,
        Err(_) => {
            cleanup_client_files(paths, id).await;
            bail!("timed out waiting for the active Iroh provider")
        }
    }
}

async fn cleanup_client_files(paths: &ControlPaths, id: &str) {
    for (dir, suffix) in [
        (&paths.requests, "req"),
        (&paths.requests, "payload"),
        (&paths.responses, "resp"),
        (&paths.responses, "body"),
    ] {
        let _ = tokio::fs::remove_file(file_for(dir, id, suffix)).await;
    }
}

fn response_error(response: &[u8]) -> anyhow::Result<Option<String>> {
    if response.len() > MAX_RESPONSE_FILE_BYTES {
        bail!("Iroh provider returned an oversized control response")
    }
    let text =
        std::str::from_utf8(response).context("Iroh provider returned invalid control text")?;
    if let Some(message) = text.strip_prefix("ERR\n") {
        return Ok(Some(
            message
                .lines()
                .next()
                .unwrap_or("provider operation failed")
                .to_owned(),
        ));
    }
    Ok(None)
}

pub async fn submit_add(paths: &ControlPaths, body: &[u8]) -> anyhow::Result<Hash> {
    if body.len() > MAX_BODY_BYTES {
        bail!("input exceeds the configured body limit")
    }
    let admission = acquire_queue_lock(paths).await?;
    check_queue_capacity(paths, body.len() as u64).await?;
    let id = new_id();
    let payload_path = file_for(&paths.requests, &id, "payload");
    let request_path = file_for(&paths.requests, &id, "req");
    atomic_write(&payload_path, body).await?;
    if let Err(error) = atomic_write(&request_path, b"ADD\n").await {
        cleanup_client_files(paths, &id).await;
        return Err(error);
    }
    drop(admission);
    let response = match wait_response(paths, &id, ADD_WAIT).await {
        Ok(response) => response,
        Err(error) => {
            cleanup_client_files(paths, &id).await;
            return Err(error);
        }
    };
    let parsed = async {
        if let Some(message) = response_error(&response)? {
            bail!("provider add failed: {message}")
        }
        let text = std::str::from_utf8(&response)
            .context("Iroh provider returned invalid add response")?;
        let hash = text
            .strip_prefix("OK\n")
            .and_then(|value| value.lines().next())
            .ok_or_else(|| anyhow!("Iroh provider returned a malformed add response"))?;
        hash.parse::<Hash>()
            .context("Iroh provider returned an invalid blob hash")
    }
    .await;
    cleanup_client_files(paths, &id).await;
    parsed
}

pub async fn submit_get(
    paths: &ControlPaths,
    hash: Hash,
    providers: &str,
) -> anyhow::Result<Vec<u8>> {
    if providers.len() > MAX_PROVIDER_CONFIG_BYTES
        || (providers.contains('\n') || providers.contains('\r'))
    {
        bail!("SPORE_IROH_PROVIDERS exceeds the control input limit")
    }
    let admission = acquire_queue_lock(paths).await?;
    check_queue_capacity(paths, MAX_BODY_BYTES as u64).await?;
    let id = new_id();
    let request_path = file_for(&paths.requests, &id, "req");
    let request = format!("GET\n{}\n{}", hash.to_hex(), providers);
    atomic_write(&request_path, request.as_bytes()).await?;
    drop(admission);
    let response = match wait_response(paths, &id, GET_WAIT).await {
        Ok(response) => response,
        Err(error) => {
            cleanup_client_files(paths, &id).await;
            return Err(error);
        }
    };
    let result = async {
        if let Some(message) = response_error(&response)? {
            bail!("provider get failed: {message}")
        }
        let text = std::str::from_utf8(&response)
            .context("Iroh provider returned invalid get response")?;
        let size = text
            .strip_prefix("OK\n")
            .and_then(|value| value.lines().next())
            .ok_or_else(|| anyhow!("Iroh provider returned a malformed get response"))?
            .parse::<usize>()
            .context("Iroh provider returned an invalid body size")?;
        if size > MAX_BODY_BYTES {
            bail!("Iroh provider response exceeds the configured body limit")
        }
        let body = read_bounded(&file_for(&paths.responses, &id, "body"), MAX_BODY_BYTES)
            .await
            .context("Iroh provider response body is missing or oversized")?;
        if body.len() != size || Hash::new(&body) != hash {
            bail!("Iroh provider response failed size or hash verification")
        }
        Ok(body)
    }
    .await;
    cleanup_client_files(paths, &id).await;
    result
}

async fn read_bounded(path: &Path, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("could not open control input {}", path.display()))?;
    read_bounded_file(file, path, max_bytes).await
}

async fn read_bounded_if_exists(path: &Path, max_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("could not open {}", path.display()));
        }
    };
    Ok(Some(read_bounded_file(file, path, max_bytes).await?))
}

async fn read_bounded_file(
    file: tokio::fs::File,
    path: &Path,
    max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("could not read control file {}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!("Iroh control file exceeds its input limit")
    }
    Ok(bytes)
}

async fn execute_request(
    store: &FsStore,
    endpoint: &Endpoint,
    paths: &ControlPaths,
    id: &str,
    request: &[u8],
) -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let text = std::str::from_utf8(request).context("control request is not UTF-8")?;
    let mut fields = text.splitn(3, '\n');
    match fields.next().unwrap_or("") {
        "ADD" if fields.next().unwrap_or_default().is_empty() && fields.next().is_none() => {
            let body =
                read_bounded(&file_for(&paths.requests, id, "payload"), MAX_BODY_BYTES).await?;
            let tag = store
                .blobs()
                .add_bytes(Bytes::from(body))
                .await
                .context("could not add blob to provider store")?;
            Ok((format!("OK\n{}\n", tag.hash.to_hex()).into_bytes(), None))
        }
        "GET" => {
            let hash_text = fields
                .next()
                .ok_or_else(|| anyhow!("get request has no locator"))?;
            let hash = hash_text
                .parse::<Hash>()
                .context("get request has an invalid locator")?;
            let providers = fields.next().unwrap_or("");
            if providers.len() > MAX_PROVIDER_CONFIG_BYTES
                || (providers.contains('\n') || providers.contains('\r'))
            {
                bail!("get request provider configuration exceeds its limit")
            }
            let body = if let Some(body) = read_local_blob(store, hash).await? {
                body
            } else {
                let provider_addrs = parse_provider_config(providers)?;
                if provider_addrs.is_empty() {
                    bail!("blob is not local and no providers are configured")
                }
                let bytes = fetch_from(endpoint, &provider_addrs, hash).await?;
                match store.blobs().add_bytes(bytes.clone()).await {
                    Ok(tag) if tag.hash == hash => {}
                    Ok(_) => bail!("cached blob hash did not match the requested locator"),
                    Err(_) => eprintln!(
                        "spore-iroh: verified transfer succeeded but local caching failed"
                    ),
                }
                bytes.to_vec()
            };
            if body.len() > MAX_BODY_BYTES || Hash::new(&body) != hash {
                bail!("provider body failed local size or hash verification")
            }
            let response = format!("OK\n{}\n", body.len()).into_bytes();
            Ok((response, Some(body)))
        }
        _ => bail!("unsupported Iroh control operation"),
    }
}

async fn process_request(
    store: &FsStore,
    endpoint: &Endpoint,
    paths: &ControlPaths,
    request_path: &Path,
) -> anyhow::Result<()> {
    let file_name = request_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("control request has an invalid filename"))?;
    let id = file_name
        .strip_suffix(".req")
        .ok_or_else(|| anyhow!("control request has an invalid suffix"))?;
    if !valid_id(id) {
        bail!("control request has an invalid id")
    }

    let result = async {
        let request = read_bounded(request_path, MAX_REQUEST_FILE_BYTES).await?;
        execute_request(store, endpoint, paths, id, &request).await
    }
    .await;

    let response = match result {
        Ok((response, Some(body))) => {
            if let Err(error) = atomic_write(&file_for(&paths.responses, id, "body"), &body).await {
                format!("ERR\n{}\n", safe_message(&error.to_string())).into_bytes()
            } else {
                response
            }
        }
        Ok((response, None)) => response,
        Err(error) => format!("ERR\n{}\n", safe_message(&error.to_string())).into_bytes(),
    };
    let write_result = atomic_write(&file_for(&paths.responses, id, "resp"), &response).await;
    let _ = tokio::fs::remove_file(request_path).await;
    let _ = tokio::fs::remove_file(file_for(&paths.requests, id, "payload")).await;
    write_result
}

fn safe_message(message: &str) -> String {
    message
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

async fn next_request(
    paths: &ControlPaths,
    active: &HashSet<PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let mut entries = tokio::fs::read_dir(&paths.requests).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.ends_with(".req") && !active.contains(&path) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

async fn prune_stale_directory(
    directory: &Path,
    suffixes: &[&str],
    now: std::time::SystemTime,
) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(".tmp-") && !suffixes.iter().any(|suffix| name.ends_with(suffix)) {
            continue;
        }
        let stale = entry
            .metadata()
            .await?
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > RESPONSE_TTL);
        if stale {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

async fn prune_stale_control_files(paths: &ControlPaths) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now();
    prune_stale_directory(&paths.requests, &[".req", ".payload"], now).await?;
    prune_stale_directory(&paths.responses, &[".resp", ".body"], now).await?;
    Ok(())
}

pub async fn run_control_loop(
    store: FsStore,
    endpoint: Endpoint,
    paths: ControlPaths,
) -> anyhow::Result<()> {
    let store = Arc::new(store);
    let endpoint = Arc::new(endpoint);
    let mut tasks = JoinSet::new();
    let mut active_paths = HashSet::new();
    let mut task_paths: HashMap<tokio::task::Id, PathBuf> = HashMap::new();
    let mut last_sweep = tokio::time::Instant::now();

    loop {
        while tasks.len() < MAX_ACTIVE_REQUESTS {
            let Some(request) = next_request(&paths, &active_paths).await? else {
                break;
            };
            active_paths.insert(request.clone());

            let task_store = Arc::clone(&store);
            let task_endpoint = Arc::clone(&endpoint);
            let task_paths_copy = paths.clone();
            let task_request = request.clone();
            let handle = tasks.spawn(async move {
                process_request(&task_store, &task_endpoint, &task_paths_copy, &task_request).await
            });
            task_paths.insert(handle.id(), request);
        }

        if tasks.is_empty() {
            if tokio::fs::try_exists(&paths.stopping)
                .await
                .unwrap_or(false)
            {
                return Ok(());
            }
            if last_sweep.elapsed() >= RESPONSE_SWEEP_INTERVAL {
                if let Err(error) = prune_stale_control_files(&paths).await {
                    eprintln!(
                        "spore-iroh: could not prune stale control files: {}",
                        safe_message(&error.to_string())
                    );
                }
                last_sweep = tokio::time::Instant::now();
            }
            sleep(POLL_INTERVAL).await;
            continue;
        }

        tokio::select! {
            joined = tasks.join_next_with_id() => match joined {
                Some(Ok((id, result))) => {
                    if let Some(request) = task_paths.remove(&id) {
                        active_paths.remove(&request);
                        if let Err(error) = result {
                            eprintln!(
                                "spore-iroh: queued operation failed: {}",
                                safe_message(&error.to_string())
                            );
                            let _ = tokio::fs::remove_file(&request).await;
                        }
                    }
                }
                Some(Err(error)) => {
                    if let Some(request) = task_paths.remove(&error.id()) {
                        active_paths.remove(&request);
                        let _ = tokio::fs::remove_file(&request).await;
                    }
                    eprintln!(
                        "spore-iroh: queued operation task failed: {}",
                        safe_message(&error.to_string())
                    );
                }
                None => {}
            },
            _ = sleep(POLL_INTERVAL) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::SystemTime};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let base = std::env::var_os("SPORE_IROH_TEST_TMPDIR")
                .or_else(|| std::env::var_os("TMPDIR"))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .expect("current directory")
                        .join("target")
                        .join("spore-iroh-control-tests")
                });
            fs::create_dir_all(&base).expect("create test scratch directory");
            let path = base.join(format!("spore-iroh-control-{}", new_id()));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn queue_lock_serializes_admission() {
        let root = TestRoot::new();
        let paths = ControlPaths::new(root.path());
        ensure_control_dirs(&paths)
            .await
            .expect("create control dirs");
        let held = try_queue_lock(&paths)
            .expect("first lock attempt")
            .expect("first request owns admission lock");
        assert!(
            try_queue_lock(&paths)
                .expect("second lock attempt")
                .is_none()
        );
        drop(held);
        assert!(
            try_queue_lock(&paths)
                .expect("third lock attempt")
                .is_some()
        );
    }

    #[tokio::test]
    async fn next_request_skips_a_request_already_in_flight() {
        let root = TestRoot::new();
        let paths = ControlPaths::new(root.path());
        ensure_control_dirs(&paths)
            .await
            .expect("create control dirs");
        let request = file_for(&paths.requests, "in-flight", "req");
        tokio::fs::write(&request, b"GET\n")
            .await
            .expect("create queued request");

        assert_eq!(
            next_request(&paths, &HashSet::new())
                .await
                .expect("scan pending queue"),
            Some(request.clone())
        );
        let active = HashSet::from([request.clone()]);
        assert_eq!(
            next_request(&paths, &active)
                .await
                .expect("scan active queue"),
            None
        );
    }

    #[tokio::test]
    async fn queue_capacity_counts_orphans_and_reserves_get_bodies() {
        let root = TestRoot::new();
        let paths = ControlPaths::new(root.path());
        ensure_control_dirs(&paths)
            .await
            .expect("create control dirs");
        for index in 0..MAX_QUEUED_REQUESTS {
            let id = format!("orphan-{index:x}");
            tokio::fs::write(file_for(&paths.requests, &id, "payload"), b"")
                .await
                .expect("create orphan payload");
        }
        assert!(check_queue_capacity(&paths, 0).await.is_err());
        clear_dir(&paths.requests)
            .await
            .expect("clear orphan payloads");
        for index in 0..4 {
            let id = format!("get-{index:x}");
            tokio::fs::write(file_for(&paths.requests, &id, "req"), b"GET\n")
                .await
                .expect("create pending GET");
        }
        check_queue_capacity(&paths, 0)
            .await
            .expect("four GETs fit the reserved body budget");
        assert!(
            check_queue_capacity(&paths, MAX_BODY_BYTES as u64)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn response_control_file_is_bounded() {
        let root = TestRoot::new();
        let paths = ControlPaths::new(root.path());
        ensure_control_dirs(&paths)
            .await
            .expect("create control dirs");
        let id = new_id();
        tokio::fs::write(
            file_for(&paths.responses, &id, "resp"),
            vec![b'x'; MAX_RESPONSE_FILE_BYTES + 1],
        )
        .await
        .expect("write oversized response");
        assert!(
            wait_response(&paths, &id, Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stale_orphaned_requests_and_responses_are_pruned() {
        let root = TestRoot::new();
        let paths = ControlPaths::new(root.path());
        ensure_control_dirs(&paths)
            .await
            .expect("create control dirs");
        let old_request = file_for(&paths.requests, "orphan", "payload");
        let old_response = file_for(&paths.responses, "abandoned", "body");
        let fresh_request = file_for(&paths.requests, "active", "req");
        for path in [&old_request, &old_response, &fresh_request] {
            fs::write(path, b"work").expect("write test control file");
        }
        let old = SystemTime::now() - RESPONSE_TTL - Duration::from_secs(5);
        for path in [&old_request, &old_response] {
            fs::OpenOptions::new()
                .write(true)
                .open(path)
                .expect("open stale file")
                .set_times(fs::FileTimes::new().set_modified(old))
                .expect("age stale file");
        }
        prune_stale_control_files(&paths)
            .await
            .expect("prune stale control files");
        assert!(!old_request.exists(), "orphan payload was retained");
        assert!(
            !old_response.exists(),
            "abandoned response body was retained"
        );
        assert!(fresh_request.exists(), "fresh queued request was removed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn store_and_control_paths_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestRoot::new();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))
            .expect("broaden test root mode");
        let _access = acquire_store_access(root.path())
            .await
            .expect("acquire private store");
        let paths = ControlPaths::new(root.path());
        let _queue_lock = try_queue_lock(&paths)
            .expect("queue lock open")
            .expect("queue lock acquired");
        for directory in [
            root.path(),
            &paths.control,
            &paths.requests,
            &paths.responses,
        ] {
            let mode = fs::metadata(directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} mode was {mode:o}", directory.display());
        }
        for lock in [root.path().join(LOCK_FILE), paths.queue_lock.clone()] {
            let mode = fs::metadata(&lock)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{} mode was {mode:o}", lock.display());
        }
    }
}
