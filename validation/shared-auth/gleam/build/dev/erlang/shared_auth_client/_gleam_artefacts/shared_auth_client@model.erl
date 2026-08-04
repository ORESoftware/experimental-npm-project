-module(shared_auth_client@model).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "src/shared_auth_client/model.gleam").
-export([challenge_kind_to_string/1, has_assurance/2, used_method/2, has_role/2, exchange_response_decoder/0, step_up_response_decoder/0, introspection_decoder/0, jwks_decoder/0, capabilities_decoder/0, factor_decoder/0, totp_enrollment_decoder/0, challenge_start_decoder/0, ceremony_start_decoder/0]).
-export_type([exchange_response/0, step_up_response/0, introspection/0, jwks/0, capabilities/0, factor/0, totp_enrollment/0, challenge_kind/0, challenge_start/0, ceremony_start/0]).

-type exchange_response() :: {exchange_response,
        binary(),
        binary(),
        integer(),
        binary(),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary())}.

-type step_up_response() :: {step_up_response,
        binary(),
        binary(),
        integer(),
        list(binary()),
        gleam@option:option(binary())}.

-type introspection() :: {introspection,
        boolean(),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        gleam@option:option(boolean()),
        list(binary()),
        list(binary()),
        gleam@option:option(binary()),
        gleam@option:option(integer())}.

-type jwks() :: {jwks, list(gleam@dynamic:dynamic_())}.

-type capabilities() :: {capabilities,
        boolean(),
        list(binary()),
        gleam@option:option(binary()),
        gleam@option:option(binary())}.

-type factor() :: {factor,
        binary(),
        binary(),
        gleam@option:option(binary()),
        boolean(),
        gleam@option:option(binary()),
        gleam@option:option(binary()),
        binary()}.

-type totp_enrollment() :: {totp_enrollment,
        binary(),
        binary(),
        binary(),
        binary()}.

-type challenge_kind() :: email_otp | sms_otp.

-type challenge_start() :: {challenge_start, binary(), binary(), binary()}.

-type ceremony_start() :: {ceremony_start,
        binary(),
        gleam@dynamic:dynamic_(),
        binary()}.

-file("src/shared_auth_client/model.gleam", 93).
-spec challenge_kind_to_string(challenge_kind()) -> binary().
challenge_kind_to_string(Kind) ->
    case Kind of
        email_otp ->
            <<"email_otp"/utf8>>;

        sms_otp ->
            <<"sms_otp"/utf8>>
    end.

-file("src/shared_auth_client/model.gleam", 100).
-spec has_assurance(introspection(), binary()) -> boolean().
has_assurance(Value, Required_acr) ->
    erlang:element(2, Value) andalso (erlang:element(13, Value) =:= {some,
        Required_acr}).

-file("src/shared_auth_client/model.gleam", 104).
-spec used_method(introspection(), binary()) -> boolean().
used_method(Value, Method) ->
    erlang:element(2, Value) andalso gleam@list:contains(
        erlang:element(12, Value),
        Method
    ).

-file("src/shared_auth_client/model.gleam", 108).
-spec has_role(introspection(), binary()) -> boolean().
has_role(Value, Role) ->
    erlang:element(2, Value) andalso gleam@list:contains(
        erlang:element(11, Value),
        Role
    ).

-file("src/shared_auth_client/model.gleam", 112).
-spec exchange_response_decoder() -> gleam@dynamic@decode:decoder(exchange_response()).
exchange_response_decoder() ->
    gleam@dynamic@decode:field(
        <<"access_token"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Access_token) ->
            gleam@dynamic@decode:field(
                <<"token_type"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_string/1},
                fun(Token_type) ->
                    gleam@dynamic@decode:field(
                        <<"expires_at"/utf8>>,
                        {decoder, fun gleam@dynamic@decode:decode_int/1},
                        fun(Expires_at) ->
                            gleam@dynamic@decode:field(
                                <<"shared_user_id"/utf8>>,
                                {decoder,
                                    fun gleam@dynamic@decode:decode_string/1},
                                fun(Shared_user_id) ->
                                    gleam@dynamic@decode:optional_field(
                                        <<"project"/utf8>>,
                                        none,
                                        gleam@dynamic@decode:optional(
                                            {decoder,
                                                fun gleam@dynamic@decode:decode_string/1}
                                        ),
                                        fun(Project) ->
                                            gleam@dynamic@decode:optional_field(
                                                <<"provider"/utf8>>,
                                                none,
                                                gleam@dynamic@decode:optional(
                                                    {decoder,
                                                        fun gleam@dynamic@decode:decode_string/1}
                                                ),
                                                fun(Provider) ->
                                                    gleam@dynamic@decode:optional_field(
                                                        <<"provider_tenant"/utf8>>,
                                                        none,
                                                        gleam@dynamic@decode:optional(
                                                            {decoder,
                                                                fun gleam@dynamic@decode:decode_string/1}
                                                        ),
                                                        fun(Provider_tenant) ->
                                                            gleam@dynamic@decode:success(
                                                                {exchange_response,
                                                                    Access_token,
                                                                    Token_type,
                                                                    Expires_at,
                                                                    Shared_user_id,
                                                                    Project,
                                                                    Provider,
                                                                    Provider_tenant}
                                                            )
                                                        end
                                                    )
                                                end
                                            )
                                        end
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 143).
-spec step_up_response_decoder() -> gleam@dynamic@decode:decoder(step_up_response()).
step_up_response_decoder() ->
    gleam@dynamic@decode:field(
        <<"access_token"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Access_token) ->
            gleam@dynamic@decode:field(
                <<"token_type"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_string/1},
                fun(Token_type) ->
                    gleam@dynamic@decode:field(
                        <<"expires_at"/utf8>>,
                        {decoder, fun gleam@dynamic@decode:decode_int/1},
                        fun(Expires_at) ->
                            gleam@dynamic@decode:optional_field(
                                <<"amr"/utf8>>,
                                [],
                                gleam@dynamic@decode:list(
                                    {decoder,
                                        fun gleam@dynamic@decode:decode_string/1}
                                ),
                                fun(Amr) ->
                                    gleam@dynamic@decode:optional_field(
                                        <<"acr"/utf8>>,
                                        none,
                                        gleam@dynamic@decode:optional(
                                            {decoder,
                                                fun gleam@dynamic@decode:decode_string/1}
                                        ),
                                        fun(Acr) ->
                                            gleam@dynamic@decode:success(
                                                {step_up_response,
                                                    Access_token,
                                                    Token_type,
                                                    Expires_at,
                                                    Amr,
                                                    Acr}
                                            )
                                        end
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 152).
-spec introspection_decoder() -> gleam@dynamic@decode:decoder(introspection()).
introspection_decoder() ->
    gleam@dynamic@decode:field(
        <<"active"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_bool/1},
        fun(Active) ->
            gleam@dynamic@decode:optional_field(
                <<"sub"/utf8>>,
                none,
                gleam@dynamic@decode:optional(
                    {decoder, fun gleam@dynamic@decode:decode_string/1}
                ),
                fun(Sub) ->
                    gleam@dynamic@decode:optional_field(
                        <<"sid"/utf8>>,
                        none,
                        gleam@dynamic@decode:optional(
                            {decoder, fun gleam@dynamic@decode:decode_string/1}
                        ),
                        fun(Sid) ->
                            gleam@dynamic@decode:optional_field(
                                <<"project"/utf8>>,
                                none,
                                gleam@dynamic@decode:optional(
                                    {decoder,
                                        fun gleam@dynamic@decode:decode_string/1}
                                ),
                                fun(Project) ->
                                    gleam@dynamic@decode:optional_field(
                                        <<"provider"/utf8>>,
                                        none,
                                        gleam@dynamic@decode:optional(
                                            {decoder,
                                                fun gleam@dynamic@decode:decode_string/1}
                                        ),
                                        fun(Provider) ->
                                            gleam@dynamic@decode:optional_field(
                                                <<"provider_tenant"/utf8>>,
                                                none,
                                                gleam@dynamic@decode:optional(
                                                    {decoder,
                                                        fun gleam@dynamic@decode:decode_string/1}
                                                ),
                                                fun(Provider_tenant) ->
                                                    gleam@dynamic@decode:optional_field(
                                                        <<"provider_subject"/utf8>>,
                                                        none,
                                                        gleam@dynamic@decode:optional(
                                                            {decoder,
                                                                fun gleam@dynamic@decode:decode_string/1}
                                                        ),
                                                        fun(Provider_subject) ->
                                                            gleam@dynamic@decode:optional_field(
                                                                <<"email"/utf8>>,
                                                                none,
                                                                gleam@dynamic@decode:optional(
                                                                    {decoder,
                                                                        fun gleam@dynamic@decode:decode_string/1}
                                                                ),
                                                                fun(Email) ->
                                                                    gleam@dynamic@decode:optional_field(
                                                                        <<"email_verified"/utf8>>,
                                                                        none,
                                                                        gleam@dynamic@decode:optional(
                                                                            {decoder,
                                                                                fun gleam@dynamic@decode:decode_bool/1}
                                                                        ),
                                                                        fun(
                                                                            Email_verified
                                                                        ) ->
                                                                            gleam@dynamic@decode:optional_field(
                                                                                <<"roles"/utf8>>,
                                                                                [],
                                                                                gleam@dynamic@decode:list(
                                                                                    {decoder,
                                                                                        fun gleam@dynamic@decode:decode_string/1}
                                                                                ),
                                                                                fun(
                                                                                    Roles
                                                                                ) ->
                                                                                    gleam@dynamic@decode:optional_field(
                                                                                        <<"amr"/utf8>>,
                                                                                        [],
                                                                                        gleam@dynamic@decode:list(
                                                                                            {decoder,
                                                                                                fun gleam@dynamic@decode:decode_string/1}
                                                                                        ),
                                                                                        fun(
                                                                                            Amr
                                                                                        ) ->
                                                                                            gleam@dynamic@decode:optional_field(
                                                                                                <<"acr"/utf8>>,
                                                                                                none,
                                                                                                gleam@dynamic@decode:optional(
                                                                                                    {decoder,
                                                                                                        fun gleam@dynamic@decode:decode_string/1}
                                                                                                ),
                                                                                                fun(
                                                                                                    Acr
                                                                                                ) ->
                                                                                                    gleam@dynamic@decode:optional_field(
                                                                                                        <<"exp"/utf8>>,
                                                                                                        none,
                                                                                                        gleam@dynamic@decode:optional(
                                                                                                            {decoder,
                                                                                                                fun gleam@dynamic@decode:decode_int/1}
                                                                                                        ),
                                                                                                        fun(
                                                                                                            Exp
                                                                                                        ) ->
                                                                                                            gleam@dynamic@decode:success(
                                                                                                                {introspection,
                                                                                                                    Active,
                                                                                                                    Sub,
                                                                                                                    Sid,
                                                                                                                    Project,
                                                                                                                    Provider,
                                                                                                                    Provider_tenant,
                                                                                                                    Provider_subject,
                                                                                                                    Email,
                                                                                                                    Email_verified,
                                                                                                                    Roles,
                                                                                                                    Amr,
                                                                                                                    Acr,
                                                                                                                    Exp}
                                                                                                            )
                                                                                                        end
                                                                                                    )
                                                                                                end
                                                                                            )
                                                                                        end
                                                                                    )
                                                                                end
                                                                            )
                                                                        end
                                                                    )
                                                                end
                                                            )
                                                        end
                                                    )
                                                end
                                            )
                                        end
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 207).
-spec jwks_decoder() -> gleam@dynamic@decode:decoder(jwks()).
jwks_decoder() ->
    gleam@dynamic@decode:field(
        <<"keys"/utf8>>,
        gleam@dynamic@decode:list(
            {decoder, fun gleam@dynamic@decode:decode_dynamic/1}
        ),
        fun(Keys) -> gleam@dynamic@decode:success({jwks, Keys}) end
    ).

-file("src/shared_auth_client/model.gleam", 212).
-spec capabilities_decoder() -> gleam@dynamic@decode:decoder(capabilities()).
capabilities_decoder() ->
    gleam@dynamic@decode:field(
        <<"mfa_enabled"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_bool/1},
        fun(Mfa_enabled) ->
            gleam@dynamic@decode:optional_field(
                <<"methods"/utf8>>,
                [],
                gleam@dynamic@decode:list(
                    {decoder, fun gleam@dynamic@decode:decode_string/1}
                ),
                fun(Methods) ->
                    gleam@dynamic@decode:optional_field(
                        <<"threefa_import_scheme"/utf8>>,
                        none,
                        gleam@dynamic@decode:optional(
                            {decoder, fun gleam@dynamic@decode:decode_string/1}
                        ),
                        fun(Threefa_import_scheme) ->
                            gleam@dynamic@decode:optional_field(
                                <<"biometric_model"/utf8>>,
                                none,
                                gleam@dynamic@decode:optional(
                                    {decoder,
                                        fun gleam@dynamic@decode:decode_string/1}
                                ),
                                fun(Biometric_model) ->
                                    gleam@dynamic@decode:success(
                                        {capabilities,
                                            Mfa_enabled,
                                            Methods,
                                            Threefa_import_scheme,
                                            Biometric_model}
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 237).
-spec factor_decoder() -> gleam@dynamic@decode:decoder(factor()).
factor_decoder() ->
    gleam@dynamic@decode:field(
        <<"factor_id"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Factor_id) ->
            gleam@dynamic@decode:field(
                <<"kind"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_string/1},
                fun(Kind) ->
                    gleam@dynamic@decode:optional_field(
                        <<"label"/utf8>>,
                        none,
                        gleam@dynamic@decode:optional(
                            {decoder, fun gleam@dynamic@decode:decode_string/1}
                        ),
                        fun(Label) ->
                            gleam@dynamic@decode:field(
                                <<"enabled"/utf8>>,
                                {decoder,
                                    fun gleam@dynamic@decode:decode_bool/1},
                                fun(Enabled) ->
                                    gleam@dynamic@decode:optional_field(
                                        <<"confirmed_at"/utf8>>,
                                        none,
                                        gleam@dynamic@decode:optional(
                                            {decoder,
                                                fun gleam@dynamic@decode:decode_string/1}
                                        ),
                                        fun(Confirmed_at) ->
                                            gleam@dynamic@decode:optional_field(
                                                <<"last_used_at"/utf8>>,
                                                none,
                                                gleam@dynamic@decode:optional(
                                                    {decoder,
                                                        fun gleam@dynamic@decode:decode_string/1}
                                                ),
                                                fun(Last_used_at) ->
                                                    gleam@dynamic@decode:field(
                                                        <<"created_at"/utf8>>,
                                                        {decoder,
                                                            fun gleam@dynamic@decode:decode_string/1},
                                                        fun(Created_at) ->
                                                            gleam@dynamic@decode:success(
                                                                {factor,
                                                                    Factor_id,
                                                                    Kind,
                                                                    Label,
                                                                    Enabled,
                                                                    Confirmed_at,
                                                                    Last_used_at,
                                                                    Created_at}
                                                            )
                                                        end
                                                    )
                                                end
                                            )
                                        end
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 268).
-spec totp_enrollment_decoder() -> gleam@dynamic@decode:decoder(totp_enrollment()).
totp_enrollment_decoder() ->
    gleam@dynamic@decode:field(
        <<"factor_id"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Factor_id) ->
            gleam@dynamic@decode:field(
                <<"secret_base32"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_string/1},
                fun(Secret_base32) ->
                    gleam@dynamic@decode:field(
                        <<"otpauth_uri"/utf8>>,
                        {decoder, fun gleam@dynamic@decode:decode_string/1},
                        fun(Otpauth_uri) ->
                            gleam@dynamic@decode:field(
                                <<"threefa_import_uri"/utf8>>,
                                {decoder,
                                    fun gleam@dynamic@decode:decode_string/1},
                                fun(Threefa_import_uri) ->
                                    gleam@dynamic@decode:success(
                                        {totp_enrollment,
                                            Factor_id,
                                            Secret_base32,
                                            Otpauth_uri,
                                            Threefa_import_uri}
                                    )
                                end
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 281).
-spec challenge_start_decoder() -> gleam@dynamic@decode:decoder(challenge_start()).
challenge_start_decoder() ->
    gleam@dynamic@decode:field(
        <<"challenge_id"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Challenge_id) ->
            gleam@dynamic@decode:field(
                <<"expires_at"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_string/1},
                fun(Expires_at) ->
                    gleam@dynamic@decode:field(
                        <<"delivery"/utf8>>,
                        {decoder, fun gleam@dynamic@decode:decode_string/1},
                        fun(Delivery) ->
                            gleam@dynamic@decode:success(
                                {challenge_start,
                                    Challenge_id,
                                    Expires_at,
                                    Delivery}
                            )
                        end
                    )
                end
            )
        end
    ).

-file("src/shared_auth_client/model.gleam", 288).
-spec ceremony_start_decoder() -> gleam@dynamic@decode:decoder(ceremony_start()).
ceremony_start_decoder() ->
    gleam@dynamic@decode:field(
        <<"challenge_id"/utf8>>,
        {decoder, fun gleam@dynamic@decode:decode_string/1},
        fun(Challenge_id) ->
            gleam@dynamic@decode:field(
                <<"options"/utf8>>,
                {decoder, fun gleam@dynamic@decode:decode_dynamic/1},
                fun(Options) ->
                    gleam@dynamic@decode:field(
                        <<"expires_at"/utf8>>,
                        {decoder, fun gleam@dynamic@decode:decode_string/1},
                        fun(Expires_at) ->
                            gleam@dynamic@decode:success(
                                {ceremony_start,
                                    Challenge_id,
                                    Options,
                                    Expires_at}
                            )
                        end
                    )
                end
            )
        end
    ).
