use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Context, bail};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::timeout,
};

const SIDECAR: &str = env!("CARGO_BIN_EXE_spore-iroh");
const CHILD_START_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_TIMEOUT: Duration = Duration::from_secs(40);
static NEXT_WORKSPACE: AtomicU64 = AtomicU64::new(0);

struct TestWorkspace(PathBuf);

impl TestWorkspace {
    fn new() -> io::Result<Self> {
        let base = std::env::var_os("SPORE_IROH_TEST_TMPDIR")
            .or_else(|| std::env::var_os("TMPDIR"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&base)?;
        let path = base.join(format!(
            "spore-iroh-it-{}-{}",
            std::process::id(),
            NEXT_WORKSPACE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn read_provider_ticket(server: &mut Child) -> anyhow::Result<String> {
    let stdout = server
        .stdout
        .take()
        .context("provider stdout was not piped")?;
    let mut lines = BufReader::new(stdout).lines();
    loop {
        let line = timeout(CHILD_START_TIMEOUT, lines.next_line())
            .await
            .context("provider did not print its ticket before the startup deadline")??;
        let Some(line) = line else {
            bail!("provider exited before publishing its ticket");
        };
        if let Some(ticket) = line.strip_prefix("provider_ticket: ") {
            if ticket.is_empty() {
                bail!("provider published an empty ticket");
            }
            return Ok(ticket.to_owned());
        }
    }
}

#[tokio::test]
async fn sidecar_processes_transfer_and_cache_a_blob_over_loopback() -> anyhow::Result<()> {
    let workspace = TestWorkspace::new()?;
    let payload_path = workspace.path().join("payload.bin");
    let provider_store = workspace.path().join("provider-store");
    let consumer_store = workspace.path().join("consumer-store");
    let payload = b"Spore Iroh process-level transfer\0binary-safe\n";
    fs::write(&payload_path, payload)?;

    let mut add = Command::new(SIDECAR);
    add.args(["blob", "add"])
        .arg(&payload_path)
        .env("SPORE_IROH_STORE", &provider_store)
        .env_remove("SPORE_IROH_PROVIDERS")
        .kill_on_drop(true);
    let add_output = timeout(CLI_TIMEOUT, add.output())
        .await
        .context("blob add timed out")??;
    if !add_output.status.success() {
        bail!(
            "blob add failed: {}",
            String::from_utf8_lossy(&add_output.stderr)
        );
    }
    let hash = String::from_utf8(add_output.stdout)?.trim().to_owned();
    if hash.is_empty() {
        bail!("blob add returned an empty locator");
    }

    let mut server = Command::new(SIDECAR)
        .args(["blob", "serve"])
        .env("SPORE_IROH_STORE", &provider_store)
        .env("SPORE_IROH_BIND_ADDR", "127.0.0.1:0")
        .env_remove("SPORE_IROH_PROVIDERS")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let ticket = read_provider_ticket(&mut server).await?;

    // A second CLI process must hand writes to the live provider rather than
    // opening a competing redb-backed FsStore in another process.
    let second_payload_path = workspace.path().join("payload-while-serving.bin");
    let second_payload = b"added while the provider remains online\0";
    fs::write(&second_payload_path, second_payload)?;
    let mut live_add = Command::new(SIDECAR);
    live_add
        .args(["blob", "add"])
        .arg(&second_payload_path)
        .env("SPORE_IROH_STORE", &provider_store)
        .env_remove("SPORE_IROH_PROVIDERS")
        .kill_on_drop(true);
    let live_add_output = timeout(CLI_TIMEOUT, live_add.output())
        .await
        .context("live provider blob add timed out")??;
    if !live_add_output.status.success() {
        bail!(
            "live provider blob add failed: {}",
            String::from_utf8_lossy(&live_add_output.stderr)
        );
    }
    let second_hash = String::from_utf8(live_add_output.stdout)?.trim().to_owned();
    if second_hash.is_empty() || second_hash == hash {
        bail!("live provider blob add returned an invalid locator");
    }

    // Several independent processes reserve and submit queue work at once.
    let mut additional_blobs = vec![(second_hash.clone(), second_payload.to_vec())];
    let mut writers = tokio::task::JoinSet::new();
    for index in 0..3 {
        let payload = format!("parallel provider write {index}\0binary").into_bytes();
        let path = workspace
            .path()
            .join(format!("payload-parallel-{index}.bin"));
        fs::write(&path, &payload)?;
        let store = provider_store.clone();
        writers.spawn(async move {
            let mut add = Command::new(SIDECAR);
            add.args(["blob", "add"])
                .arg(path)
                .env("SPORE_IROH_STORE", store)
                .env_remove("SPORE_IROH_PROVIDERS")
                .kill_on_drop(true);
            let output = timeout(CLI_TIMEOUT, add.output())
                .await
                .context("parallel live add timed out")??;
            if !output.status.success() {
                bail!(
                    "parallel live add failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let hash = String::from_utf8(output.stdout)?.trim().to_owned();
            if hash.is_empty() {
                bail!("parallel live add returned an empty locator");
            }
            Ok::<_, anyhow::Error>((hash, payload))
        });
    }
    while let Some(result) = writers.join_next().await {
        let (new_hash, new_payload) = result.context("parallel live add task panicked")??;
        if additional_blobs
            .iter()
            .any(|(existing, _)| existing == &new_hash)
        {
            bail!("parallel live adds returned a duplicate locator");
        }
        additional_blobs.push((new_hash, new_payload));
    }

    for (additional_hash, expected) in &additional_blobs {
        let mut provider_local_get = Command::new(SIDECAR);
        provider_local_get
            .args(["blob", "get", additional_hash])
            .env("SPORE_IROH_STORE", &provider_store)
            .env_remove("SPORE_IROH_PROVIDERS")
            .kill_on_drop(true);
        let provider_local_output = timeout(CLI_TIMEOUT, provider_local_get.output())
            .await
            .context("provider-local get timed out")??;
        if !provider_local_output.status.success() {
            bail!(
                "provider-local get failed: {}",
                String::from_utf8_lossy(&provider_local_output.stderr)
            );
        }
        assert_eq!(&provider_local_output.stdout, expected);
    }

    // Keep a sidecar online for the isolated consumer store so the parallel
    // GET clients exercise the bounded control worker pool, not the local lock.
    let mut consumer_server = Command::new(SIDECAR)
        .args(["blob", "serve"])
        .env("SPORE_IROH_STORE", &consumer_store)
        .env("SPORE_IROH_PROVIDERS", &ticket)
        .env("SPORE_IROH_BIND_ADDR", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let _consumer_ticket = read_provider_ticket(&mut consumer_server).await?;

    let mut get = Command::new(SIDECAR);
    get.args(["blob", "get", &hash])
        .env("SPORE_IROH_STORE", &consumer_store)
        .env("SPORE_IROH_PROVIDERS", &ticket)
        .env("SPORE_IROH_BIND_ADDR", "127.0.0.1:0")
        .kill_on_drop(true);
    let get_output = timeout(CLI_TIMEOUT, get.output())
        .await
        .context("loopback blob get timed out")??;
    if !get_output.status.success() {
        let _ = server.kill().await;
        let _ = server.wait().await;
        bail!(
            "loopback blob get failed: {}",
            String::from_utf8_lossy(&get_output.stderr)
        );
    }
    assert_eq!(get_output.stdout, payload);

    let mut readers = tokio::task::JoinSet::new();
    for (additional_hash, expected) in &additional_blobs {
        let hash = additional_hash.clone();
        let expected = expected.clone();
        let store = consumer_store.clone();
        let providers = ticket.clone();
        readers.spawn(async move {
            let mut get = Command::new(SIDECAR);
            get.args(["blob", "get", &hash])
                .env("SPORE_IROH_STORE", store)
                .env("SPORE_IROH_PROVIDERS", providers)
                .env("SPORE_IROH_BIND_ADDR", "127.0.0.1:0")
                .kill_on_drop(true);
            let output = timeout(CLI_TIMEOUT, get.output())
                .await
                .context("parallel loopback blob get timed out")??;
            if !output.status.success() {
                bail!(
                    "parallel loopback get failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if output.stdout != expected {
                bail!("parallel loopback get returned a body mismatch");
            }
            Ok::<_, anyhow::Error>(())
        });
    }
    while let Some(result) = readers.join_next().await {
        result.context("parallel loopback get task panicked")??;
    }

    // The second retrieval must be served from the isolated consumer store;
    // remove provider configuration to prove it does not dial the server.
    let mut cached_get = Command::new(SIDECAR);
    cached_get
        .args(["blob", "get", &hash])
        .env("SPORE_IROH_STORE", &consumer_store)
        .env_remove("SPORE_IROH_PROVIDERS")
        .kill_on_drop(true);
    let cached_output = timeout(CLI_TIMEOUT, cached_get.output())
        .await
        .context("cached blob get timed out")??;
    assert!(
        cached_output.status.success(),
        "cached get failed: {}",
        String::from_utf8_lossy(&cached_output.stderr)
    );
    assert_eq!(cached_output.stdout, payload);

    server.kill().await?;
    let _ = server.wait().await?;
    Ok(())
}

#[tokio::test]
async fn sidecar_rejects_oversized_input_before_opening_store() -> anyhow::Result<()> {
    let workspace = TestWorkspace::new()?;
    let payload_path = workspace.path().join("oversized.bin");
    let store_path = workspace.path().join("must-not-be-created");
    let file = fs::File::create(&payload_path)?;
    file.set_len(20 * 1024 * 1024 + 1)?;

    let mut add = Command::new(SIDECAR);
    add.args(["blob", "add"])
        .arg(&payload_path)
        .env("SPORE_IROH_STORE", &store_path)
        .kill_on_drop(true);
    let output = timeout(CLI_TIMEOUT, add.output())
        .await
        .context("oversized-input check timed out")??;
    assert!(!output.status.success(), "oversized input was accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("body limit"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !store_path.exists(),
        "store was opened before size rejection"
    );
    Ok(())
}
