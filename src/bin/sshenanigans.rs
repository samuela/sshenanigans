use anyhow::{bail, Context};
use async_trait::async_trait;
use clap::Parser;
use dashmap::DashMap;
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
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

struct AbortOnDrop {
  inner: tokio::task::AbortHandle,
}
impl AbortOnDrop {
  fn new<T>(inner: tokio::task::JoinHandle<T>) -> Self {
    Self {
      inner: inner.abort_handle(),
    }
  }
}
impl Drop for AbortOnDrop {
  fn drop(&mut self) {
    self.inner.abort();
  }
}

struct Server {
  gatekeeper_command: PathBuf,
  gatekeeper_args: Vec<String>,
}

struct PtyStuff {
  requested_col_width: u16,
  requested_row_height: u16,
  pts: pty_process::Pts,
  pty_writer: OwnedWritePty,
}

/// A type representing the state of a channel. `ServerHandler` is a state
/// machine that transitions between these states as the SSH client sends
/// requests. Most of the action is in `SshenanigansChannelType`.
struct SshenanigansChannel {
  /// Environment variables requested by the client via `env_request`.
  requested_environment_variables: HashMap<String, String>,

  state: SshenanigansChannelState,
}

/// The state of a channel.
///
/// For each channel, a handle that when dropped will abort a tokio task
/// owning the corresponding child process for that channel. This is necessary
/// to prevent process leakage. There are two ways these Droppings come in
/// handy:
/// 1. We manually drop these in `close_channel` to kill the child process.
/// 2. `ServerHandler` will be dropped when the SSH client disconnects,
///    cleanly or not. This can happen eg when the inactivity timeout
///    threshold is violated. When this happens, the `ServerHandler` will be
///    dropped (https://github.com/warp-tech/russh/issues/229), which will
///    drop all `AbortOnDrop`s, which will abort their corresponding tokio
///    tasks, each of which own a `tokio::process::Child` process. These
///    children have `kill_on_drop(true)` set, so they will be killed by tokio
///    automatically.
///
/// Note that we can't actually own the `Child` in these since `child.wait()`,
/// takes ownership.
enum SshenanigansChannelState {
  /// Every channel starts out life as an `Uninitialized` channel in
  /// `channel_open_session`.
  Uninitialized,

  /// An `Uninitialized` channel is converted into `PtyExec` channel in
  /// `pty_request`.
  PtyExec {
    _child_abort_handle: Option<AbortOnDrop>,
    stuff: PtyStuff,
  },

  /// An `Uninitialized` channel is converted into a `NonPtyExec` channel by
  /// `shell_request` or `exec_request` that is not preceded by a `pty_request`.
  NonPtyExec {
    _child_abort_handle: AbortOnDrop,
    stdin_writer: tokio::process::ChildStdin,
  },
}

struct ServerHandler {
  tracing_span: tracing::Span,

  gatekeeper_command: PathBuf,
  gatekeeper_args: Vec<String>,

  /// A random UUID assigned to each client.
  client_id: Uuid,

  /// The IP address of the client.
  client_address: Option<SocketAddr>,

  /// The SSH protocol associates each channel with a user. This value will only be `Some` after a successful
  /// authentication.
  verified_credentials: Option<Credentials>,

  channels: Arc<DashMap<ChannelId, SshenanigansChannel>>,
}

impl russh::server::Server for Server {
  type Handler = ServerHandler;

  #[tracing::instrument(skip(self))]
  fn new_client(&mut self, client_address: Option<SocketAddr>) -> ServerHandler {
    // Peculiar though it may be, it is possible in practice for
    // `client_address` to be `None`. This seems to trace all the way back to
    // getpeername errors. So far, the cleanest way to handle this seems to be
    // to propagate the `Option`-ality all the way down and return `Err` types
    // when we encounter a `None`.
    //
    // See https://github.com/warp-tech/russh/issues/226.

    let client_id = Uuid::new_v4();
    ServerHandler {
      // No need to add client_address as a field, since this span's parent will
      // be the one created by `tracing::instrument` on `new_client`.
      tracing_span: tracing::span!(tracing::Level::INFO, "connection", ?client_id),
      gatekeeper_command: self.gatekeeper_command.clone(),
      gatekeeper_args: self.gatekeeper_args.clone(),
      client_id,
      client_address,
      verified_credentials: None,
      channels: Arc::new(DashMap::new()),
    }
  }

  fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
    tracing::error!(?error, "session error");
  }
}

#[tracing::instrument(skip(handle))]
async fn close_channel(
  client_address: Option<SocketAddr>,
  client_id: Uuid,
  handle: &russh::server::Handle,
  channel_id: ChannelId,
  exit_status: &std::process::ExitStatus,
) {
  // NOTE: .code() can return None when the child process is killed via a
  // signal like ctrl-c.
  let our_exit_status: u32 = match (exit_status.code(), exit_status.signal()) {
    (Some(code), None) => code.try_into().unwrap_or(1),
    (None, Some(signal)) => signal as u32 + 128,
    _ => unreachable!(),
  };

  // Note: these can fail. I have no idea why.
  if let Err(error) = handle.exit_status_request(channel_id, our_exit_status).await {
    tracing::error!(?error, "sending exit status failed");
  }
  if let Err(error) = handle.eof(channel_id).await {
    tracing::error!(?error, "sending eof failed");
  }
  if let Err(error) = handle.close(channel_id).await {
    tracing::error!(?error, "sending close failed");
  }
}

#[tracing::instrument(level = "trace", skip(handle))]
async fn send_data(
  client_address: Option<SocketAddr>,
  client_id: Uuid,
  channel_id: ChannelId,
  handle: &russh::server::Handle,
  data: &[u8],
) {
  // Note: this can sometimes result in an Err. Possibly due to the SSH client
  // closing the channel before we can finish writing to it?
  //
  // TODO: debug and come up with a better solution
  if let Err(error) = handle.data(channel_id, CryptoVec::from_slice(data)).await {
    tracing::error!(?error, "sending data failed");
  }
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
  // NOTE: we don't log `request` since it can contain passwords.
  #[tracing::instrument(level = "debug", skip(self, request))]
  fn gatekeeper_call<O: DeserializeOwned>(&self, request: RequestType) -> anyhow::Result<O> {
    let start_time = std::time::Instant::now();

    let client_address = self.client_address.context("expected client_address")?.to_string();
    let request = Request {
      client_address,
      client_id: self.client_id.to_string(),
      request,
    };

    // The Gatekeeper is trusted and therefore does not require `env_clear()`.
    let mut child = std::process::Command::new(&self.gatekeeper_command)
      .args(&self.gatekeeper_args)
      .stdin(std::process::Stdio::piped())
      .stdout(std::process::Stdio::piped())
      .spawn()?;
    tracing::debug!(pid = child.id(), "gatekeeper child spawned");

    // Write the details to the child's stdin.
    child
      .stdin
      .as_mut()
      .context("Failed to get stdin for gatekeeper child")?
      .write_all(
        serde_json::to_string(&request)
          .context("Failed to serialize request as JSON")?
          .as_bytes(),
      )
      .context("Failed to write to gatekeeper child stdin")?;

    let output = child
      .wait_with_output()
      .context("Failed to wait for gatekeeper child")?;
    tracing::debug!(
      elapsed = ?start_time.elapsed(),
      ?output,
      "gatekeeper finished"
    );

    let exit_status = output.status;
    if exit_status.success() {
      serde_json::from_slice(&output.stdout).context("Failed to parse gatekeeper stdout")
    } else {
      bail!("The Gatekeeper exited with a non-zero status code, {exit_status}. The Gatekeeper should never exit with a non-zero status code, even when rejecting requests.");
    }
  }

  /// Send an auth request to the gatekeeper and parse its response.
  // NOTE: we don't log `unverified_credentials` since it can contain passwords.
  #[tracing::instrument(level = "debug", skip(self, unverified_credentials))]
  fn gatekeeper_make_auth_request(
    self,
    unverified_credentials: &Credentials,
  ) -> Result<(ServerHandler, Auth), <Self as russh::server::Handler>::Error> {
    let response: AuthResponse = self
      .gatekeeper_call(RequestType::Auth {
        unverified_credentials: unverified_credentials.clone(),
      })
      .context("Failed to call gatekeeper")?;

    Ok(match response {
      AuthResponse { accept: true, .. } => {
        tracing::info!("gatekeeper accepted auth request");
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
        tracing::info!(?proceed_with_methods, "gatekeeper rejected auth request");
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

  /// Spawn a task to wait on the child process and then close the SSH channel
  /// with the exit code. Move ownership of the child process to the task, and
  /// return an `AbortOnDrop` handle to the task.
  #[tracing::instrument(level = "debug", skip(self, handle, child), fields(child_pid = child.id().unwrap()))]
  async fn wait_and_close_channel(
    &self,
    channel_id: ChannelId,
    handle: russh::server::Handle,
    mut child: tokio::process::Child,
  ) -> AbortOnDrop {
    let client_address_ = self.client_address;
    let client_id_ = self.client_id;
    AbortOnDrop::new(tokio::spawn(async move {
      let exit_status = child.wait().await.unwrap();
      close_channel(client_address_, client_id_, &handle, channel_id, &exit_status).await;
      drop(child);
    }))
  }

  /// Execute a command in a given PTY. Upon exit, close the SSH channel.
  // `command_spec` tends to be quite verbose and can possibly contain secrets,
  // so we don't log it.
  #[tracing::instrument(level = "debug", skip(self, handle, pty_stuff, command_spec))]
  async fn pty_exec(
    &self,
    channel_id: ChannelId,
    handle: russh::server::Handle,
    pty_stuff: &PtyStuff,
    command_spec: &ExecResponseAccept,
  ) -> Result<AbortOnDrop, <Self as russh::server::Handler>::Error> {
    // Spawn a new process in pty
    let child = pty_process::Command::new(&command_spec.command)
          // Security critial: Use `env_clear()` so we don't inherit environment
          // variables from the parent process.
          .env_clear()
          // kill_on_drop(true) is essential to prevent leaking processes.
          .kill_on_drop(true)
          .envs(&command_spec.environment_variables)
          .args(&command_spec.arguments)
          .current_dir(&command_spec.working_directory)
          .uid(command_spec.uid)
          .gid(command_spec.gid)
          .spawn(&pty_stuff.pts)
          .context("Failed to spawn child process. This can happen due to working_directory not existing, or insufficient permissions to set uid/gid.")?;
    tracing::info!(pid = child.id(), "child spawned");

    // Do this before resizing the PTY, in case the resize fails.
    let wait_handle = self.wait_and_close_channel(channel_id, handle, child).await;

    // Notes:
    // 1. We already set up a task to read from the PTY and send to the SSH
    //    client in `pty_request`, so we don't need to do it here.
    // 2. We must resize the PTY according to the requested size. We don't do
    //    this at PTY creation time since we can't resize until after the child
    //    is spawned on macOS. See https://github.com/doy/pty-process/issues/7#issuecomment-1826196215
    //    and https://github.com/pkgw/stund/issues/305.
    // 3. `pty_process::Size::new` flips the order of col_width and row_height!
    pty_stuff.pty_writer.resize(pty_process::Size::new(
      pty_stuff.requested_row_height,
      pty_stuff.requested_col_width,
    ))?;

    Ok(wait_handle)
  }

  /// Execute a command without a PTY.
  #[tracing::instrument(level = "debug", skip(self, handle, command_spec))]
  async fn non_pty_exec(
    &self,
    channel_id: ChannelId,
    handle: russh::server::Handle,
    command_spec: &ExecResponseAccept,
  ) -> Result<(tokio::process::ChildStdin, AbortOnDrop), <Self as russh::server::Handler>::Error> {
    let mut child = tokio::process::Command::new(&command_spec.command)
          // Security critial: Use `env_clear()` so we don't inherit environment
          // variables from the parent process.
          .env_clear()
          // kill_on_drop(true) is essential to prevent leaking processes.
          .kill_on_drop(true)
          .envs(&command_spec.environment_variables)
          .args(&command_spec.arguments)
          .current_dir(&command_spec.working_directory)
          .uid(command_spec.uid)
          .gid(command_spec.gid)
          .stdin(std::process::Stdio::piped())
          .stdout(std::process::Stdio::piped())
          .stderr(std::process::Stdio::piped())
          .spawn()
          .context("Failed to spawn child process. This can happen due to working_directory not existing, or insufficient permissions to set uid/gid.")?;
    tracing::info!(pid = child.id(), "child spawned");

    // Read bytes from the child stdout and send them to the SSH client
    let mut stdout = child.stdout.take().context("Failed to get stdout for child process")?;
    let handle_ = handle.clone();
    let client_address_ = self.client_address;
    let client_id_ = self.client_id;
    tokio::spawn(async move {
      let mut buffer = vec![0; 1024];
      while let Ok(n) = stdout.read(&mut buffer).await {
        if n == 0 {
          break;
        }
        send_data(client_address_, client_id_, channel_id, &handle_, &buffer[0..n]).await;
      }
    });
    // Now, same for stderr...
    let mut stderr = child.stderr.take().context("Failed to get stderr for child process")?;
    let handle_ = handle.clone();
    tokio::spawn(async move {
      let mut buffer = vec![0; 1024];
      while let Ok(n) = stderr.read(&mut buffer).await {
        if n == 0 {
          break;
        }
        send_data(client_address_, client_id_, channel_id, &handle_, &buffer[0..n]).await;
      }
    });

    let stdin = child.stdin.take().context("Failed to get stdin for child process")?;
    // Note: we would like to do this as early as possible in case of Err
    // short- circuiting the function, but it consumes ownership of `child`.
    let wait_handle = self.wait_and_close_channel(channel_id, handle, child).await;
    Ok((stdin, wait_handle))
  }
}

#[async_trait]
impl russh::server::Handler for ServerHandler {
  type Error = anyhow::Error;

  #[tracing::instrument(parent = &self.tracing_span, skip(self))]
  async fn auth_none(self, username: &str) -> Result<(Self, Auth), Self::Error> {
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::None,
    })
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, password))]
  async fn auth_password(self, username: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::Password {
        password: password.to_owned(),
      },
    })
  }

  // `public_key` Debug prints in a format that is basically worthless.
  #[tracing::instrument(parent = &self.tracing_span, skip(self, public_key))]
  async fn auth_publickey(
    self,
    username: &str,
    public_key: &russh_keys::key::PublicKey,
  ) -> Result<(Self, Auth), Self::Error> {
    let public_key_algorithm = public_key.name().to_owned();
    let public_key_base64 = public_key.public_key_base64();
    tracing::info!(public_key_algorithm, public_key_base64);
    self.gatekeeper_make_auth_request(&Credentials {
      username: username.to_owned(),
      method: CredentialsType::PublicKey {
        public_key_algorithm,
        public_key_base64,
      },
    })
  }

  // Not a lot of logic here, but russh requires this handler.
  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn channel_open_session(
    self,
    channel: Channel<Msg>,
    session: Session,
  ) -> Result<(Self, bool, Session), Self::Error> {
    // Note: We don't guard against clobbering an existing channel id.
    self.channels.insert(
      channel.id(),
      SshenanigansChannel {
        requested_environment_variables: HashMap::new(),
        state: SshenanigansChannelState::Uninitialized,
      },
    );
    Ok((self, true, session))
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn pty_request(
    self,
    channel_id: ChannelId,
    term: &str,
    col_width: u32,
    row_height: u32,
    _pix_width: u32,
    _pix_height: u32,
    modes: &[(russh::Pty, u32)],
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;
      match channel.state {
        SshenanigansChannelState::Uninitialized => {
          // TODO: We're currently ignoring the requested modes. We should
          // probably do something with them.

          let pty = pty_process::Pty::new().context("Failed to create PTY")?;
          // NOTE: we must get `pts` before `.into_split()` because it consumes
          // the PTY.
          let pts = pty.pts().context("Failed to get pts")?;

          // split pty into reader + writer
          let (mut pty_reader, pty_writer) = pty.into_split();

          // Insert all the goodies into `self.channels`. We save the requested
          // terminal size so we can resize the PTY later in `shell_request`.
          // Most clients seem to send a `pty_request` before a `shell_request`,
          // and it's not clear that sending `pty_request` after `shell_request`
          // is support by the SSH spec or makes any sense.
          channel.state = SshenanigansChannelState::PtyExec {
            _child_abort_handle: None,
            stuff: PtyStuff {
              requested_col_width: col_width as u16,
              requested_row_height: row_height as u16,
              pts,
              pty_writer,
            },
          };

          // Read bytes from the PTY and send them to the SSH client
          let session_handle = session.handle();
          tokio::spawn(async move {
            let mut buffer = vec![0; 1024];
            while let Ok(n) = pty_reader.read(&mut buffer).await {
              if n == 0 {
                break;
              }
              send_data(
                self.client_address,
                self.client_id,
                channel_id,
                &session_handle,
                &buffer[0..n],
              )
              .await;
            }
          });
        }
        _ => bail!("expected Uninitialized channel"),
      }
    }
    Ok((self, session))
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn env_request(
    self,
    channel_id: ChannelId,
    variable_name: &str,
    variable_value: &str,
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;
      channel
        .requested_environment_variables
        .insert(variable_name.to_owned(), variable_value.to_owned());
    }
    Ok((self, session))
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn shell_request(self, channel_id: ChannelId, session: Session) -> Result<(Self, Session), Self::Error> {
    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;

      let resp: ExecResponse = self.gatekeeper_call(RequestType::Shell {
        verified_credentials: self
          .verified_credentials
          .clone()
          .context("shell_request called when verified_credentials is None")?,
        requested_environment_variables: channel.requested_environment_variables.clone(),
      })?;
      let accept = resp.accept.context("gatekeeper denied request")?;

      let handle = session.handle();
      match &mut channel.state {
        SshenanigansChannelState::Uninitialized => {
          let (stdin_writer, _child_abort_handle) = self.non_pty_exec(channel_id, handle, &accept).await?;
          channel.state = SshenanigansChannelState::NonPtyExec {
            _child_abort_handle,
            stdin_writer,
          };
        }
        SshenanigansChannelState::PtyExec {
          ref mut _child_abort_handle,
          stuff,
        } => {
          let handle = self.pty_exec(channel_id, handle, &stuff, &accept).await?;
          *_child_abort_handle = Some(handle);
        }
        _ => bail!("expected Uninitialized or PtyExec channel"),
      }
    }

    Ok((self, session))
  }

  /// SSH client sends data, pipe it to the corresponding PTY or stdin
  #[tracing::instrument(parent = &self.tracing_span, skip(self, session), level = "trace")]
  async fn data(self, channel_id: ChannelId, data: &[u8], session: Session) -> Result<(Self, Session), Self::Error> {
    tracing::trace!(data_utf8 = ?String::from_utf8_lossy(data));
    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;
      match channel.state {
        SshenanigansChannelState::PtyExec {
          stuff: PtyStuff { ref mut pty_writer, .. },
          ..
        } => {
          tracing::trace!(?data, "writing to pty_writer");
          pty_writer.write_all(data).await.context("Failed to write to PTY")?;
        }
        SshenanigansChannelState::NonPtyExec {
          ref mut stdin_writer, ..
        } => {
          tracing::trace!(?data, "writing to stdin_writer");
          stdin_writer.write_all(data).await.context("Failed to write to stdin")?;
        }
        _ => bail!("expected PtyExec or NonPtyExec channel"),
      }
    }
    Ok((self, session))
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, command, session))]
  async fn exec_request(
    self,
    channel_id: ChannelId,
    command: &[u8],
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    let command_string = String::from_utf8(command.to_vec())?;
    tracing::info!(?command_string);

    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;

      let resp: ExecResponse = self.gatekeeper_call(RequestType::Exec {
        verified_credentials: self
          .verified_credentials
          .clone()
          .context("exec_request called when verified_credentials is None")?,
        requested_environment_variables: channel.requested_environment_variables.clone(),
        command: command_string,
      })?;
      let accept = resp.accept.context("gatekeeper denied request")?;

      let handle = session.handle();
      match &mut channel.state {
        SshenanigansChannelState::Uninitialized => {
          let (stdin_writer, _child_abort_handle) = self.non_pty_exec(channel_id, handle, &accept).await?;
          channel.state = SshenanigansChannelState::NonPtyExec {
            _child_abort_handle,
            stdin_writer,
          };
        }
        SshenanigansChannelState::PtyExec {
          ref mut _child_abort_handle,
          stuff,
        } => {
          let handle = self.pty_exec(channel_id, handle, &stuff, &accept).await?;
          *_child_abort_handle = Some(handle);
        }
        _ => bail!("expected Uninitialized or PtyExec channel"),
      }
    }
    Ok((self, session))
  }

  /// The client's pseudo-terminal window size has changed.
  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn window_change_request(
    self,
    channel_id: ChannelId,
    col_width: u32,
    row_height: u32,
    _pix_width: u32,
    _pix_height: u32,
    session: Session,
  ) -> Result<(Self, Session), Self::Error> {
    {
      let mut channel = self.channels.get_mut(&channel_id).context("channel_id not found")?;
      match channel.state {
        SshenanigansChannelState::PtyExec {
          stuff: PtyStuff { ref mut pty_writer, .. },
          ..
        } => {
          pty_writer.resize(pty_process::Size::new(row_height as u16, col_width as u16))?;
        }
        _ => bail!("expected PtyExec channel"),
      }
    }
    Ok((self, session))
  }

  #[tracing::instrument(parent = &self.tracing_span, skip(self, session))]
  async fn channel_close(self, channel_id: ChannelId, session: Session) -> Result<(Self, Session), Self::Error> {
    // Removing from `self.channdels` and dropping results in the corresponding
    // child process being killed. Besides avoiding a memory leak, this is
    // important since we don't want to leak processes. Child processes will be
    // killed since their associated channel struct will contain `AbortOnDrop`s
    // which contain `tokio::task::AbortHandle`s for tokio tasks that own
    // `tokio::process::Child`s that have `kill_on_drop(true)` set.
    drop(self.channels.remove(&channel_id));
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

  /// Optionally drop privileges to this user after binding to the socket.
  #[arg(long)]
  setuid: Option<u32>,

  /// Optionally drop privileges to this group after binding to the socket.
  #[arg(long)]
  setgid: Option<u32>,
}

fn load_host_keys(host_key_paths: Vec<PathBuf>) -> Vec<russh_keys::key::KeyPair> {
  if host_key_paths.is_empty() {
    tracing::error!("At least one --host-key-path is required");
    std::process::exit(1);
  }

  host_key_paths
    .iter()
    .map(|path| {
      // NOTE: we don't support encrypted keys or "~/foo" paths yet.
      russh_keys::load_secret_key(path, None).unwrap_or_else(|error| {
        tracing::error!(?path, ?error, "Failed to load host key");
        std::process::exit(1);
      })
    })
    .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  tracing_subscriber::registry()
    .with(
      tracing_subscriber::fmt::layer()
        .pretty()
        // Use span events to automatically log each of the SSH handlers.
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW),
    )
    .with(tracing_subscriber::EnvFilter::from_default_env())
    .init();

  let args = Args::parse();

  let gatekeeper_split = args.gatekeeper.split_whitespace().collect::<Vec<&str>>();
  assert!(!gatekeeper_split.is_empty(), "gatekeeper command must not be empty");

  let config = russh::server::Config {
    inactivity_timeout: Some(std::time::Duration::from_secs(30 * 60)),
    auth_rejection_time: std::time::Duration::from_secs(1),
    keys: load_host_keys(args.host_key_path),
    ..Default::default()
  };

  let socket = tokio::net::TcpListener::bind(&args.listen).await.context(format!(
    "Failed to bind to socket {}. Are you sure you have permissions to bind to the given socket address?",
    args.listen
  ))?;

  // setgid before setuid, since generally speaking we won't have permission to
  // setgid after setuid.
  if let Some(gid) = args.setgid {
    tracing::info!(gid, "dropping gid privileges");
    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid)).context("failed to drop privileges with setgid")?;
  }
  if let Some(uid) = args.setuid {
    tracing::info!(uid, "dropping uid privileges");
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid)).context("failed to drop privileges with setuid")?;
  }

  tracing::info!(listening_on = args.listen.to_string(), "listening on socket");
  russh::server::run_on_socket(
    Arc::new(config),
    &socket,
    Server {
      // This indexing is safe since we assert that `gatekeeper_split` is not empty above.
      gatekeeper_command: gatekeeper_split[0].into(),
      gatekeeper_args: gatekeeper_split[1..].iter().map(|s| s.to_string()).collect(),
    },
  )
  .await
  .context("Failed to run SSH server main loop")?;

  Ok(())
}
