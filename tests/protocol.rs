use sshenanigans::ExecResponse;

#[test]
fn environment_variables_is_required() {
  let mut response = serde_json::json!({
    "accept": {
      "command": "/bin/sh",
      "arguments": [],
      "working_directory": "/",
      "uid": 1000,
      "gid": 1000
    }
  });

  let error = serde_json::from_value::<ExecResponse>(response.clone()).err().unwrap();
  assert!(error.to_string().contains("missing field `environment_variables`"));

  response["accept"]["environment_variables"] = serde_json::json!({});
  let parsed: ExecResponse = serde_json::from_value(response).unwrap();
  assert!(parsed.accept.unwrap().environment_variables.is_empty());
}
