use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub enum AuthRequestMethod {
  None,
  Password {
    password: String,
  },
  PublicKey {
    public_key_algorithm: String,
    public_key_base64: String,
  },
}

#[derive(Serialize)]
pub enum Request {
  /// Examples:
  ///   - {'Auth': {'client_address': '127.0.0.1:51591', 'username': 'skainswo', 'method': {'Password': {'password': 'topsecret'}}}}
  ///   - {'Auth': {'client_address': '127.0.0.1:51636', 'username': 'skainswo', 'method': {'PublicKey': {'public_key_algorithm': 'ssh-ed25519', 'public_key_base64': 'AAA...wLq'}}}}
  Auth {
    client_address: String,
    username: String,
    method: AuthRequestMethod,
  },
  /// Example: {'Shell': {'client_address': '127.0.0.1:51591', 'username': 'skainswo'}}
  Shell { client_address: String, username: String },
  /// Example: {'Exec': {'client_address': '127.0.0.1:56797', 'username': 'skainswo', 'command': 'ls -al'}}
  Exec {
    client_address: String,
    username: String,
    command: String,
  },
}

/// This is the response to a Request::Shell or Request::Exec request.
#[derive(Deserialize)]
pub struct ExecResponse {
  pub accept: Option<ExecResponseAccept>,
}

#[derive(Deserialize)]
pub struct ExecResponseAccept {
  /// The command to execute.
  pub command: String,
  /// Arguments to pass to the command.
  pub arguments: Vec<String>,
  /// The working directory to execute the command in.
  pub working_directory: String,
  /// The user to execute the command as.
  pub uid: u32,
  /// The group to execute the command as.
  pub gid: u32,
}

#[derive(Deserialize)]
pub struct AuthResponse {
  pub accept: bool,
  /// Allowed values are specified in https://docs.rs/russh/latest/russh/struct.MethodSet.html. Currently they are
  /// "NONE", "PASSWORD", "PUBLICKEY", "HOSTBASED", "KEYBOARD_INTERACTIVE" (case sensitive). A value is recommended when
  /// accept is false.
  pub proceed_with_methods: Option<Vec<String>>,
}
