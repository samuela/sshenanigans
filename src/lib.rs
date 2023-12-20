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
pub enum RequestType {
  Auth {
    username: String,
    method: AuthRequestMethod,
  },
  Shell {
    username: String,
  },
  Exec {
    username: String,
    command: String,
  },
}

#[derive(Serialize)]
/// Example Auth requests:
///   - {'client_address': '127.0.0.1:50710', 'request': {'Auth': {'username': 'sam', 'method': 'None'}}}
///   - {'client_address': '127.0.0.1:51591', 'request': {'Auth': {'username': 'sam', 'method': {'Password': {'password': 'topsecret'}}}}}
///   - {'client_address': '127.0.0.1:51636', 'request': {'Auth': {'username': 'sam', 'method': {'PublicKey': {'public_key_algorithm': 'ssh-ed25519', 'public_key_base64': 'AAA...wLq'}}}}}
///
/// Example Shell requests:
///   - {'client_address': '127.0.0.1:51591', 'request': {'Shell': {'username': 'skainswo'}}}
///
/// Example Exec requests:
///   - {'client_address': '127.0.0.1:56797', 'request': {'Exec': {'username': 'skainswo', 'command': 'ls -al'}}}
pub struct Request {
  /// The address of the client that sent the request.
  pub client_address: String,
  /// The request.
  pub request: RequestType,
}

/// This is the response to a Request::Shell or Request::Exec request.
#[derive(Deserialize)]
pub struct ExecResponse {
  /// If this is Some, then the request will be accepted and the command will be executed as specified. If this is None,
  /// then the request will be rejected.
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
  /// Whether to accept the authentication request.
  pub accept: bool,
  /// Allowed values are specified in https://docs.rs/russh/latest/russh/struct.MethodSet.html. Currently they are
  /// "NONE", "PASSWORD", "PUBLICKEY", "HOSTBASED", "KEYBOARD_INTERACTIVE" (case sensitive). A value is recommended when
  /// accept is false.
  pub proceed_with_methods: Option<Vec<String>>,
}
