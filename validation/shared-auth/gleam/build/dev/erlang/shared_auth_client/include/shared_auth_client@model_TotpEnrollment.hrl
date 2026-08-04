-record(totp_enrollment, {
    factor_id :: binary(),
    secret_base32 :: binary(),
    otpauth_uri :: binary(),
    threefa_import_uri :: binary()
}).
