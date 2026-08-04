{application, shared_auth_client, [
    {vsn, "0.1.0"},
    {applications, [gleam_http,
                    gleam_httpc,
                    gleam_json,
                    gleam_stdlib,
                    gleeunit]},
    {description, "Thin typed Gleam client for the shared-auth HTTP API."},
    {modules, [shared_auth_client,
               shared_auth_client@@main,
               shared_auth_client@model,
               shared_auth_client_test]},
    {registered, []}
]}.
