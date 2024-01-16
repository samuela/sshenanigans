use async_trait::async_trait;
use clap::Parser;
use pty_process::OwnedWritePty;
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodSet};
use russh_keys::PublicKeyBase64;
use serde::de::DeserializeOwned;
use sshenanigans::{
  AuthResponse, Credentials, CredentialsType, ExecResponse, ExecResponseAccept, Request, RequestType,
};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

struct Server {
  gatekeeper_command: PathBuf,
  gatekeeper_args: Vec<String>,
}

type ChannelValue<T> = Arc<Mutex<HashMap<ChannelId, T>>>;

/// The requested PTY size (col, row), PTS, and writer to the PTY.
struct PtyStuff {
  requested_col_width: u16,
  requested_row_height: u16,
  pts: pty_process::Pts,
  pty_writer: OwnedWritePty,
}

struct ServerHandler {
  gatekeeper_command: PathBuf,
  gatekeeper_args: Vec<String>,

  /// A random UUID assigned to each client.
  client_id: Uuid,

  /// The IP address of the client.
  client_address: std::net::SocketAddr,

  /// The SSH protocol associates each channel with a user. This value will only be `Some` after a successful
  /// authentication.
  verified_credentials: Option<Credentials>,

  /// Environment variables requested by the client via `env_request`.
  requested_environment_variables: HashMap<String, String>,

  ptys: ChannelValue<PtyStuff>,

  /// Writer to the stdin of the child process associated with a channel.
  stdin_writers: ChannelValue<tokio::process::ChildStdin>,
}

impl russh::server::Server for Server {
  type Handler = ServerHandler;
  fn new_client(&mut self, client_address: Option<std::net::SocketAddr>) -> ServerHandler {
    // NOTE: it's unclear from the russh docs how we would ever get a None value here.
    let client_address = client_address.expect("client_address is None");
    let client_id = Uuid::new_v4();
    log::info!("[{}] new client, assigning id {client_id}", client_address);
    ServerHandler {
      gatekeeper_command: self.gatekeeper_command.clone(),
      gatekeeper_args: self.gatekeeper_args.clone(),
      client_id,
      client_address,
      verified_credentials: None,
      requested_environment_variables: HashMap::new(),
      ptys: Arc::new(Mutex::new(HashMap::new())),
      stdin_writers: Arc::new(Mutex::new(HashMap::new())),
    }
  }
}

async fn close_channel(handle: &russh::server::Handle, channel_id: ChannelId, exit_status: &std::process::ExitStatus) {
  // NOTE: .code() can return None when the child process is killed via a
  // signal like ctrl-c.
  let our_exit_status: u32 = match (exit_status.code(), exit_status.signal()) {
    (Some(code), None) => code.try_into().unwrap_or(1),
    (None, Some(signal)) => signal as u32 + 128,
    _ => unreachable!(),
  };

  handle.exit_status_request(channel_id, our_exit_status).await.unwrap();
  handle.eof(channel_id).await.unwrap();
  handle.close(channel_id).await.unwrap();
}

/// SSH server flow for shell with PTY (eg `ssh foo@bar`):
/// 1. Client connects and a new ServerHandler is created.
/// 2. auth method, eg. auth_publickey
/// 3. channel_open_session
/// 4. pty_request
/// 5. shell_request
///
/// SSH server flow for shell without PTY (eg `ssh -T foo@bar`):
/// 1. Client connects and a new ServerHandler is created.
/// 2. auth method, eg. auth_publickey
/// 3. channel_open_session
/// 4. shell_request
///
/// SSH server flow for exec (eg `ssh foo@bar ls -la`):
/// 1. Client connects and a new ServerHandler is created.
/// 2. auth method, eg. auth_publickey
/// 3. channel_open_session
/// 4. exec_request
///
/// It's also possible to run exec commands with a PTY, eg `ssh -t foo@bar ls -al`. That just introduces a `pty_request`
/// in the flow.
impl ServerHandler {
  /// Talk to the gatekeeper and parse its response.
  fn gatekeeper_call<O: DeserializeOwned>(&self, request: &Request) -> O {
    let start_time = std::time::Instant::now();
    // The Gatekeeper is trusted and therefore does not require `env_clear()`.
    let mut child = std::process::Command::new(&self.gatekeeper_command)
      .args(&self.gatekeeper_args)
      .stdin(std::process::Stdio::piped())
      .stdout(std::process::Stdio::piped())
      .spawn()
      .unwrap_or_else(|err| {
        log::error!(
          "[{} {}] failed to spawn gatekeeper: {err:?}",
          self.client_address,
          self.client_id,
        );
        // If we can't spawn the gatekeeper, we can't do much else, so we exit.
        std::process::exit(1);
      });
    // NOTE: we don't log `request` since it can contain passwords.
    log::debug!(
      "[{} {}] gatekeeper child spawned with pid: {}",
      self.client_address,
      self.client_id,
      child.id()
    );

    // Write the details to the child's stdin.
    child
      .stdin
      .as_mut()
      .unwrap()
      .write_all(serde_json::to_string(&request).unwrap().as_bytes())
      .unwrap();

    let output = child.wait_with_output().unwrap();
    log::debug!(
      "[{} {}] gatekeeper took {:.2?}, output: {:?}",
      self.client_address,
      self.client_id,
      start_time.elapsed(),
      output
    );

    assert!(
      output.status.success(),
      "[{} {}] gatekeeper exited with a non-zero status code: {:?}",
      self.client_address,
      self.client_id,
      output.status.code().unwrap()
    );

    serde_json::from_slice(&output.stdout).expect("Failed to parse gatekeeper stdout")
  }

  /// Send an auth request to the gatekeeper and parse its response.
  fn gatekeeper_make_auth_request(
    self,
    unverified_credentials: &Credentials,
  ) -> Result<(ServerHandler, Auth), <Self as russh::server::Handler>::Error> {
    let response: AuthResponse = self.gatekeeper_call(&Request {
      client_address: self.client_address.to_string(),
      client_id: self.client_id.to_string(),
      request: RequestType::Auth {
        unverified_credentials: unverified_credentials.clone(),
      },
    });

    Ok(match response {
      AuthResponse { accept: true, .. } => {
        log::info!(
          "[{} {}] received {{ accept: true }} from gatekeeper",
          self.client_address,
          self.client_id,
        );
        (
          Self {
            verified_credentials: Some(unverified_credentials.clone()),
            ..self
          },
          russh::server::Auth::Accept,
        )
      }
      AuthResponse {
        accept: false,
        proceed_with_methods,
        ..
      } => {
        log::info!(
          "[{} {}] received {{ accept: false, proceed_with_methods: {:?} }} from gatekeeper",
          self.client_address,
          self.client_id,
          proceed_with_methods
        );
        (
          Self {
            verified_credentials: None,
            ..self
          },
          russh::server::Auth::Reject {
            proceed_with_methods: proceed_with_methods.map(|methods| {
              MethodSet::from_iter(
                methods
                  .iter()
                  .map(|method| MethodSet::from_name(method).expect("Bad method name in `proceed_with_methods`. Allowed values are 'NONE', 'PASSWORD', 'PUBLICKEY', 'HOSTBASED', 'KEYBOARD_INTERACTIVE' (case sensitive).")),
              )
            }),
          },
        )
      }
    })
  }

  async fn gatekeeper_handle_exec_response(
    &self,
    channel_id: ChannelId,
    session: &mut Session,
    response: ExecResponse,
  ) {
    match response.accept {
      Some(cmd) => {
        log::debug!("gatekeeper accepted exec request");

        let handle = session.handle();
        match self.ptys.lock().await.get(&channel_id) {
          Some(pty_stuff) => self.pty_exec(channel_id, handle, pty_stuff, &cmd).await,
          None => self.non_pty_exec(channel_id, handle, &cmd).await,
        }
      }
      None => {
        log::debug!("gatekeeper rejected exec request");
        session.eof(channel_id);
        session.close(channel_id);
      }
    }
  }

  /// Execute a command in a given PTY. Upon exit, close the SSH channel.
  async fn pty_exec(
    &self,
    channel_id: ChannelId,
    handle: russh::server::Handle,
    pty_stuff: &PtyStuff,
    command_spec: &ExecResponseAccept,
  ) {
    // Spawn a new process in pty
    let mut child = pty_process::Command::new(&command_spec.command)
          // Security critial: Use `env_clear()` so we don't inherit environment
          // variables from the parent process.
          .env_clear()
          .envs(&command_spec.environment_variables)
          .args(&command_spec.arguments)
          .current_dir(&command_spec.working_directory)
          .uid(command_spec.uid)
          .gid(command_spec.gid)
          .spawn(&pty_stuff.pts)
          .expect("Failed to spawn child process. This can happen due to working_directory not existing, or insufficient permissions to set uid/gid.");
    log::info!(
      "[{} {} {}] child spawned with pid: {}",
      self.client_address,
      self.client_id,
      channel_id,
      child.id().unwrap()
    );

    // NOTE: we already set up a task to read from the PTY and send to the SSH client in `pty_request`, so we don't need
    // to do it here.

    // Close the channel when child exits
    let ptys_ = Arc::clone(&self.ptys);
    tokio::spawn(async move {
      close_channel(&handle, channel_id, &child.wait().await.unwrap()).await;

      // Clean up things from our `pty_writers` and `pty_requested_sizes` `HashMap`s
      ptys_.lock().await.remove(&channel_id);
    });

    // Resize the PTY according to the requested size. We don't do this at PTY creation time since we can't resize until
    // after the child is spawned on macOS. See https://github.com/doy/pty-process/issues/7#issuecomment-1826196215 and
    // https://github.com/pkgw/stund/issues/305.

    // NOTE: pty_process::Size::new flips the order of col_width and row_height!
    if let Err(e) = pty_stuff.pty_writer.resize(pty_process::Size::new(
      pty_stuff.requested_row_height,
      pty_stuff.requested_col_width,
    )) {
      log::error!("pty.resize failed: {:?}", e);
    }
  }

  /// Execute a command without a PTY.
  async fn non_pty_exec(
    &self,
    channel_id: ChannelId,
    handle: russh::server::Handle,
    command_spec: &ExecResponseAccept,
  ) {
    // Spawn a new process in pty
    let mut child = tokio::process::Command::new(&command_spec.command)
          // Security critial: Use `env_clear()` so we don't inherit environment
          // variables from the parent process.
          .env_clear()
          .envs(&command_spec.environment_variables)
          .args(&command_spec.arguments)
          .current_dir(&command_spec.working_directory)
          .uid(command_spec.uid)
          .gid(command_spec.gid)
          .stdin(std::process::Stdio::piped())
          .stdout(std::process::Stdio::piped())
          .stderr(std::process::Stdio::piped())
          .spawn()
          .expect("Failed to spawn child process. This can happen due to working_directory not existing, or insufficient permissions to set uid/gid.");
    log::info!("child spawned with pid: {}", child.id().unwrap());

    // Add stdin to our stdin_writers `HashMap` so that we can write to it later in `data`
    let stdin = child.stdin.take().unwrap();
    self.stdin_writers.lock().await.insert(channel_id, stdin);

    // Read bytes from the child stdout and send them to the SSH client
    let mut stdout = child.stdout.take().unwrap();
    let handle_ = handle.clone();
    tokio::spawn(async move {
      let mut buffer = vec![0; 1024];
      while let Ok(n) = stdout.read(&mut buffer).await {
        if n == 0 {
          break;
        }
        handle_
          .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
          .await
          .unwrap();
      }
    });
    // Now, same for stderr...
    let mut stderr = child.stderr.take().unwrap();
    let handle_ = handle.clone();
    tokio::spawn(async move {
      let mut buffer = vec![0; 1024];
      while let Ok(n) = stderr.read(&mut buffer).await {
        if n == 0 {
          break;
        }
        // TODO: this can sometimes result in a panic. Possibly due to the SSH client closing the channel before the
        // child process is done writing to stderr? Or the child process exits, causing us to close the channel, and
        // then we keep trying to write the remainder of stderr to the channel?
        //
        // Either way, we should fix, possibly with `tokio::select`. Bug will affect stdout as well.
        handle_
          .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
          .await
          .unwrap();
      }
    });

    // Close the channel when child exits
    tokio::spawn(async move {
      close_channel(&handle, channel_id, &child.wait().await.unwrap()).await;
    });
  }
}

#[async_trait]
impl russh::server::Handler for ServerHandler {
  type Error = anyhow::Error;

  async fn auth_none(self, username: &str) -> Result<(Self, Auth), Self::Error> {
    log::info!(
      "[{} {}] auth_none: username: {username}",
      self.client_address,
      self.client_id
    );
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::None,
    })
  }

  async fn auth_password(self, username: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
    log::info!(
      "[{} {}] auth_password: username: {username}",
      self.client_address,
      self.client_id
    );
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::Password {
        password: password.to_owned(),
      },
    })
  }

  async fn auth_publickey(
    self,
    username: &str,
    public_key: &russh_keys::key::PublicKey,
  ) -> Result<(Self, Auth), Self::Error> {
    let public_key_algorithm = public_key.name().to_owned();
    let public_key_base64 = public_key.public_key_base64();
    log::info!("[{} {}] auth_publickey: username: {username} public_key_algorithm: {public_key_algorithm} public_key_base64: {public_key_base64}", self.client_address, self.client_id);
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::PublicKey {
        public_key_algorithm,
        public_key_base64,
      },
    })
  }

  // Not a lot of logic here, but russh requires this handler.
  async fn channel_open_session(
    self,
    channel: Channel<Msg>,
    session: Session,
  ) -> Result<(Self, bool, Session), Self::Error> {
    log::info!(
      "[{} {} {}] channel_open_session",
      self.client_address,
      self.client_id,
      channel.id()
    );
    Ok((self, true, session))
  }

  async fn pty_request(
    self,
    channel_id: ChannelId,
    term: &str,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    modes: &[(russh::Pty, u32)],
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    log::info!("[{} {} {}] pty_request, channel_id: {channel_id}, term: {term}, col_width: {col_width}, row_height: {row_height}, pix_width: {pix_width}, pix_height: {pix_height}, modes: {modes:?}", self.client_address, self.client_id, channel_id);

    // TODO: We're currently ignoring the requested modes. We should probably do something with them.

    let pty = pty_process::Pty::new().unwrap();
    // NOTE: we must get `pts` before `.into_split()` because it consumes the PTY.
    let pts = pty.pts().unwrap();

    // split pty into reader + writer
    let (mut pty_reader, pty_writer) = pty.into_split();

    // Insert all the goodies into `self.ptys`. We save the requested terminal size so we can resize the PTY later in
    // `shell_request`. Most clients seem to send a `pty_request` before a `shell_request`, and it's not clear that
    // sending `pty_request` after `shell_request` is support by the SSH spec.
    self.ptys.lock().await.insert(
      channel_id,
      PtyStuff {
        requested_col_width: col_width as u16,
        requested_row_height: row_height as u16,
        pts,
        pty_writer,
      },
    );

    // Read bytes from the PTY and send them to the SSH client
    let session_handle = session.handle();
    tokio::spawn(async move {
      let mut buffer = vec![0; 1024];
      while let Ok(n) = pty_reader.read(&mut buffer).await {
        if n == 0 {
          break;
        }
        session_handle
          .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
          .await
          .unwrap();
      }
    });

    Ok((self, session))
  }

  async fn env_request(
    self,
    channel: ChannelId,
    variable_name: &str,
    variable_value: &str,
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    log::info!(
      "[{} {} {}] env_request: {variable_name}={variable_value}",
      self.client_address,
      self.client_id,
      channel,
    );

    let mut env = self.requested_environment_variables;
    env.insert(variable_name.to_owned(), variable_value.to_owned());

    Ok((
      Self {
        requested_environment_variables: env,
        ..self
      },
      session,
    ))
  }

  async fn shell_request(self, channel_id: ChannelId, mut session: Session) -> Result<(Self, Session), Self::Error> {
    log::info!(
      "[{} {} {}] shell_request",
      self.client_address,
      self.client_id,
      channel_id
    );

    let resp: ExecResponse = self.gatekeeper_call(&Request {
      client_address: self.client_address.to_string(),
      client_id: self.client_id.to_string(),
      request: RequestType::Shell {
        verified_credentials: self
          .verified_credentials
          .clone()
          .expect("shell_request called when verified_credentials is None"),
        requested_environment_variables: self.requested_environment_variables.clone(),
      },
    });
    self
      .gatekeeper_handle_exec_response(channel_id, &mut session, resp)
      .await;

    Ok((self, session))
  }

  /// SSH client sends data, pipe it to the corresponding PTY or stdin
  async fn data(self, channel_id: ChannelId, data: &[u8], session: Session) -> Result<(Self, Session), Self::Error> {
    if let Some(PtyStuff { pty_writer, .. }) = self.ptys.lock().await.get_mut(&channel_id) {
      log::debug!("pty_writer: data = {data:02x?}");
      pty_writer.write_all(data).await.unwrap();
    } else if let Some(stdin_writer) = self.stdin_writers.lock().await.get_mut(&channel_id) {
      log::debug!("stdin_writer: data = {data:02x?}");
      stdin_writer.write_all(data).await.unwrap();
    } else {
      log::warn!("could not find outlet for data from {channel_id}, skipping write")
    }

    Ok((self, session))
  }

  async fn exec_request(
    self,
    channel_id: ChannelId,
    command: &[u8],
    mut session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    let command_string = String::from_utf8(command.to_vec())?;
    log::info!(
      "[{} {} {}] exec_request: command: {command_string}",
      self.client_address,
      self.client_id,
      channel_id
    );

    let resp: ExecResponse = self.gatekeeper_call(&Request {
      client_address: self.client_address.to_string(),
      client_id: self.client_id.to_string(),
      request: RequestType::Exec {
        verified_credentials: self
          .verified_credentials
          .clone()
          .expect("exec_request called when verified_credentials is None"),
        requested_environment_variables: self.requested_environment_variables.clone(),
        command: command_string.to_string(),
      },
    });
    self
      .gatekeeper_handle_exec_response(channel_id, &mut session, resp)
      .await;

    Ok((self, session))
  }

  /// The client's pseudo-terminal window size has changed.
  async fn window_change_request(
    self,
    channel_id: ChannelId,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    log::info!("[{} {} {}] window_change_request col_width = {col_width} row_height = {row_height}, pix_width = {pix_width}, pix_height = {pix_height}", self.client_address, self.client_id, channel_id);
    if let Some(PtyStuff { pty_writer, .. }) = self.ptys.lock().await.get_mut(&channel_id) {
      if let Err(e) = pty_writer.resize(pty_process::Size::new(row_height as u16, col_width as u16)) {
        log::error!("pty.resize failed: {:?}", e);
      }
    } else {
      log::warn!("ptys doesn't contain channel_id: {channel_id}, skipping pty resize")
    }

    Ok((self, session))
  }

  async fn channel_close(self, channel_id: ChannelId, session: Session) -> Result<(Self, Session), Self::Error> {
    log::info!(
      "[{} {} {}] channel_close",
      self.client_address,
      self.client_id,
      channel_id
    );

    // Clean up things from our `HashMap`s
    self.ptys.lock().await.remove(&channel_id);
    self.stdin_writers.lock().await.remove(&channel_id);

    Ok((self, session))
  }
}

/// A lightweight, extensible SSH server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
  /// Path to private key files for the host. Can be specified multiple times, and at least one is required.
  #[arg(long)]
  host_key_path: Vec<PathBuf>,

  /// Address to listen on.
  // Supporting multiple addresses is blocked on https://github.com/warp-tech/russh/issues/223.
  #[arg(long, default_value = "0.0.0.0:22")]
  listen: SocketAddr,

  /// The Gatekeeper command. Note that relative paths must start with ./ or similar.
  #[arg(long)]
  gatekeeper: String,
}

fn load_host_keys(host_key_paths: Vec<PathBuf>) -> Vec<russh_keys::key::KeyPair> {
  if host_key_paths.is_empty() {
    log::error!("At least one --host-key-path is required");
    std::process::exit(1);
  }

  host_key_paths
    .iter()
    .map(|path| {
      // NOTE: we don't support encrypted keys
      russh_keys::load_secret_key(path, None).unwrap_or_else(|err| {
        log::error!("Failed to load host key {}: {err:?}", path.to_string_lossy());
        std::process::exit(1);
      })
    })
    .collect()
}

#[tokio::main]
async fn main() {
  env_logger::builder().init();

  let args = Args::parse();
  log::info!("args: {:?}", args);

  let gatekeeper_split = args.gatekeeper.split_whitespace().collect::<Vec<&str>>();
  assert!(!gatekeeper_split.is_empty(), "gatekeeper command must not be empty");

  let config = russh::server::Config {
    inactivity_timeout: Some(std::time::Duration::from_secs(30 * 60)),
    auth_rejection_time: std::time::Duration::from_secs(1),
    keys: load_host_keys(args.host_key_path),
    ..Default::default()
  };
  log::info!("Listening on {}", args.listen);
  russh::server::run(
    Arc::new(config),
    &args.listen,
    Server {
      // This indexing is safe since we assert that `gatekeeper_split` is not empty above.
      gatekeeper_command: gatekeeper_split[0].into(),
      gatekeeper_args: gatekeeper_split[1..].iter().map(|s| s.to_string()).collect(),
    },
  )
  .await
  .expect("Failed to start SSH server. Are you sure you have permissions to bind to the given socket address?");
}
