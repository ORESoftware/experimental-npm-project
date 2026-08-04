-record(client, {
    base :: binary(),
    service_credential :: gleam@option:option(binary()),
    timeout_ms :: integer(),
    transport :: fun((gleam@http@request:request(binary()), integer()) -> {ok,
            gleam@http@response:response(binary())} |
        {error, gleam@httpc:http_error()})
}).
