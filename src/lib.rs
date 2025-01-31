use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

#[derive(Serialize, Clone)]
pub enum CredentialsType {
  None,
  Password {
    password: String,
  },
  PublicKey {
    public_key_algorithm: String,
    public_key_base64: String,
  },
}

#[derive(Serialize, Clone)]
pub struct Credentials {
  pub username: String,
  pub method: CredentialsType,
}

#[derive(Serialize)]
pub enum RequestType {
  Auth {
    unverified_credentials: Credentials,
  },
  Shell {
    verified_credentials: Credentials,
    requested_environment_variables: HashMap<String, String>,
  },
  Exec {
    verified_credentials: Credentials,
    requested_environment_variables: HashMap<String, String>,
    command: String,
  },
  LocalPortForward {
    verified_credentials: Credentials,
    host_to_connect: String,
    port_to_connect: u32,
    originator_address: String,
    originator_port: u32,
  },
  Subsystem {
    verified_credentials: Credentials,
    requested_environment_variables: HashMap<String, String>,
    subsystem: String,
  },
}

#[derive(Serialize)]
/// See ./examples/basic.py for example values.
pub struct Request {
  /// The address of the client that sent the request.
  pub client_address: String,

  /// A unique identifier for the client connection. These are assigned randomly
  /// by sshenanigans upon receiving a new connection. `client_id` can be used
  /// to identify a client across multiple gatekeeper requests. Note however
  /// that a single user or machine may maintain multiple connections, each with
  /// their own `client_id`, in the same way that you may have multiple browser
  /// tabs connected to the same website.
  pub client_id: String,

  /// The request.
  pub request: RequestType,
}

/// This is the response to a Request::Shell or Request::Exec request.
#[derive(Deserialize)]
pub struct ExecResponse {
  /// If this is Some, then the request will be accepted and the command will be
  /// executed as specified. If this is None, then the request will be rejected.
  pub accept: Option<ExecResponseAccept>,
}

#[derive(Deserialize)]
pub struct ExecResponseAccept {
  /// The command to execute.
  pub command: PathBuf,
  /// Arguments to pass to the command.
  pub arguments: Vec<String>,
  /// The working directory to execute the command in.
  pub working_directory: PathBuf,
  /// Environment variables to set for the command.
  pub environment_variables: HashMap<String, String>,
  /// The user to execute the command as.
  pub uid: u32,
  /// The group to execute the command as.
  pub gid: u32,
}

#[derive(Deserialize)]
pub struct AuthResponse {
  /// Whether to accept the authentication request.
  pub accept: bool,
  /// Allowed values are specified in <https://docs.rs/russh/latest/russh/struct.MethodSet.html>.
  /// Currently they are "NONE", "PASSWORD", "PUBLICKEY", "HOSTBASED",
  /// "KEYBOARD_INTERACTIVE" (case sensitive). A value is recommended when
  /// accept is false.
  pub proceed_with_methods: Option<Vec<String>>,
}
