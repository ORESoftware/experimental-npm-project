-record(factor, {
    factor_id :: binary(),
    kind :: binary(),
    label :: gleam@option:option(binary()),
    enabled :: boolean(),
    confirmed_at :: gleam@option:option(binary()),
    last_used_at :: gleam@option:option(binary()),
    created_at :: binary()
}).
