-record(step_up_response, {
    access_token :: binary(),
    token_type :: binary(),
    expires_at :: integer(),
    amr :: list(binary()),
    acr :: gleam@option:option(binary())
}).
