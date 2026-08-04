-record(exchange_response, {
    access_token :: binary(),
    token_type :: binary(),
    expires_at :: integer(),
    shared_user_id :: binary(),
    project :: gleam@option:option(binary()),
    provider :: gleam@option:option(binary()),
    provider_tenant :: gleam@option:option(binary())
}).
