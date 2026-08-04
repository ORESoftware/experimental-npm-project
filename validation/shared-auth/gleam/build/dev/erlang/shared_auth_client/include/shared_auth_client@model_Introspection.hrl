-record(introspection, {
    active :: boolean(),
    sub :: gleam@option:option(binary()),
    sid :: gleam@option:option(binary()),
    project :: gleam@option:option(binary()),
    provider :: gleam@option:option(binary()),
    provider_tenant :: gleam@option:option(binary()),
    provider_subject :: gleam@option:option(binary()),
    email :: gleam@option:option(binary()),
    email_verified :: gleam@option:option(boolean()),
    roles :: list(binary()),
    amr :: list(binary()),
    acr :: gleam@option:option(binary()),
    exp :: gleam@option:option(integer())
}).
