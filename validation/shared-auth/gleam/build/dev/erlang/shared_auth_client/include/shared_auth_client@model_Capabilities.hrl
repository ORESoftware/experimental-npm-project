-record(capabilities, {
    mfa_enabled :: boolean(),
    methods :: list(binary()),
    threefa_import_scheme :: gleam@option:option(binary()),
    biometric_model :: gleam@option:option(binary())
}).
