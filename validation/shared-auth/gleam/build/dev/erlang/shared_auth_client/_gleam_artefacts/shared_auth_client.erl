-module(shared_auth_client).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "src/shared_auth_client.gleam").
-export([new/1, with_service_credential/2, without_service_credential/1, with_timeout/2, with_transport/2, has_assurance/2, used_method/2, has_role/2, exchange/2, introspect/2, verify/2, jwks/1, capabilities/1, factors/2, enroll_totp/3, confirm_totp/4, delete_factor/3, create_challenge/3, verify_challenge/4, start_passkey_registration/3, finish_passkey_registration/5, start_passkey_authentication/2, finish_passkey_authentication/4]).
-export_type([client_error/0, client/0]).

-if(?OTP_RELEASE >= 27).
-define(MODULEDOC(Str), -moduledoc(Str)).
-define(DOC(Str), -doc(Str)).
-else.
-define(MODULEDOC(Str), -compile([])).
-define(DOC(Str), -compile([])).
-endif.

?MODULEDOC(
    " Thin, typed Gleam client for the shared-auth HTTP API.\n"
    "\n"
    " Guard orchestration, the dual-auth race, and limited HTML remain in\n"
    " shared-auth-lib. This module implements transport verbs only.\n"
).

-type client_error() :: unauthorized |
    missing_service_credential |
    {unexpected_status, integer()} |
    invalid_url |
    invalid_timeout |
    {invalid_response, gleam@json:decode_error()} |
    {transport_error, gleam@httpc:http_error()}.

-opaque client() :: {client,
        binary(),
        gleam@option:option(binary()),
        integer(),
        fun((gleam@http@request:request(binary()), integer()) -> {ok,
                gleam@http@response:response(binary())} |
            {error, gleam@httpc:http_error()})}.

-file("src/shared_auth_client.gleam", 343).
-spec default_transport(gleam@http@request:request(binary()), integer()) -> {ok,
        gleam@http@response:response(binary())} |
    {error, gleam@httpc:http_error()}.
default_transport(Req, Timeout_ms) ->
    _pipe = gleam@httpc:configure(),
    _pipe@1 = gleam@httpc:timeout(_pipe, Timeout_ms),
    _pipe@2 = gleam@httpc:follow_redirects(_pipe@1, false),
    gleam@httpc:dispatch(_pipe@2, Req).

-file("src/shared_auth_client.gleam", 452).
-spec trim_trailing_slashes(binary()) -> binary().
trim_trailing_slashes(Value) ->
    case gleam_stdlib:string_ends_with(Value, <<"/"/utf8>>) of
        true ->
            _pipe = Value,
            _pipe@1 = gleam_stdlib:string_remove_suffix(_pipe, <<"/"/utf8>>),
            trim_trailing_slashes(_pipe@1);

        false ->
            Value
    end.

-file("src/shared_auth_client.gleam", 448).
-spec normalize_base(binary()) -> binary().
normalize_base(Base) ->
    _pipe = Base,
    _pipe@1 = gleam@string:trim(_pipe),
    trim_trailing_slashes(_pipe@1).

-file("src/shared_auth_client.gleam", 48).
?DOC(
    " Construct a client with TLS verification, redirects disabled, and a\n"
    " ten-second response deadline.\n"
).
-spec new(binary()) -> {ok, client()} | {error, client_error()}.
new(Base) ->
    Base@1 = normalize_base(Base),
    case gleam@http@request:to(<<Base@1/binary, "/healthz"/utf8>>) of
        {ok, _} ->
            {ok, {client, Base@1, none, 10000, fun default_transport/2}};

        {error, _} ->
            {error, invalid_url}
    end.

-file("src/shared_auth_client.gleam", 63).
?DOC(" Attach the service bearer used only by protected introspection.\n").
-spec with_service_credential(client(), binary()) -> client().
with_service_credential(Client, Credential) ->
    {client,
        erlang:element(2, Client),
        begin
            _pipe = Credential,
            _pipe@1 = gleam@string:trim(_pipe),
            gleam@string:to_option(_pipe@1)
        end,
        erlang:element(4, Client),
        erlang:element(5, Client)}.

-file("src/shared_auth_client.gleam", 70).
-spec without_service_credential(client()) -> client().
without_service_credential(Client) ->
    {client,
        erlang:element(2, Client),
        none,
        erlang:element(4, Client),
        erlang:element(5, Client)}.

-file("src/shared_auth_client.gleam", 74).
-spec with_timeout(client(), integer()) -> {ok, client()} |
    {error, client_error()}.
with_timeout(Client, Timeout_ms) ->
    case Timeout_ms > 0 of
        true ->
            {ok,
                {client,
                    erlang:element(2, Client),
                    erlang:element(3, Client),
                    Timeout_ms,
                    erlang:element(5, Client)}};

        false ->
            {error, invalid_timeout}
    end.

-file("src/shared_auth_client.gleam", 84).
-spec with_transport(
    client(),
    fun((gleam@http@request:request(binary()), integer()) -> {ok,
            gleam@http@response:response(binary())} |
        {error, gleam@httpc:http_error()})
) -> client().
with_transport(Client, Transport) ->
    {client,
        erlang:element(2, Client),
        erlang:element(3, Client),
        erlang:element(4, Client),
        Transport}.

-file("src/shared_auth_client.gleam", 88).
-spec has_assurance(shared_auth_client@model:introspection(), binary()) -> boolean().
has_assurance(Value, Required_acr) ->
    shared_auth_client@model:has_assurance(Value, Required_acr).

-file("src/shared_auth_client.gleam", 92).
-spec used_method(shared_auth_client@model:introspection(), binary()) -> boolean().
used_method(Value, Method) ->
    shared_auth_client@model:used_method(Value, Method).

-file("src/shared_auth_client.gleam", 96).
-spec has_role(shared_auth_client@model:introspection(), binary()) -> boolean().
has_role(Value, Role) ->
    shared_auth_client@model:has_role(Value, Role).

-file("src/shared_auth_client.gleam", 444).
-spec is_success(integer()) -> boolean().
is_success(Status) ->
    (Status >= 200) andalso (Status < 300).

-file("src/shared_auth_client.gleam", 427).
-spec decode_json_response(
    gleam@http@response:response(binary()),
    gleam@dynamic@decode:decoder(AMH)
) -> {ok, AMH} | {error, client_error()}.
decode_json_response(Response, Decoder) ->
    case erlang:element(2, Response) of
        401 ->
            {error, unauthorized};

        Status ->
            case is_success(Status) of
                true ->
                    _pipe = erlang:element(4, Response),
                    _pipe@1 = gleam@json:parse(_pipe, Decoder),
                    gleam@result:map_error(
                        _pipe@1,
                        fun(Field@0) -> {invalid_response, Field@0} end
                    );

                false ->
                    {error, {unexpected_status, Status}}
            end
    end.

-file("src/shared_auth_client.gleam", 419).
-spec send(client(), gleam@http@request:request(binary())) -> {ok,
        gleam@http@response:response(binary())} |
    {error, client_error()}.
send(Client, Req) ->
    _pipe = (erlang:element(5, Client))(Req, erlang:element(4, Client)),
    gleam@result:map_error(
        _pipe,
        fun(Field@0) -> {transport_error, Field@0} end
    ).

-file("src/shared_auth_client.gleam", 385).
-spec build_request(
    client(),
    gleam@http:method(),
    binary(),
    gleam@option:option(binary()),
    gleam@option:option(gleam@json:json())
) -> {ok, gleam@http@request:request(binary())} | {error, client_error()}.
build_request(Client, Method, Path, Bearer, Body) ->
    case gleam@http@request:to(
        <<(erlang:element(2, Client))/binary, Path/binary>>
    ) of
        {error, _} ->
            {error, invalid_url};

        {ok, Req} ->
            Req@1 = begin
                _pipe = Req,
                _pipe@1 = gleam@http@request:set_method(_pipe, Method),
                gleam@http@request:set_header(
                    _pipe@1,
                    <<"accept"/utf8>>,
                    <<"application/json"/utf8>>
                )
            end,
            Req@2 = case Bearer of
                {some, Token} ->
                    gleam@http@request:set_header(
                        Req@1,
                        <<"authorization"/utf8>>,
                        <<"Bearer "/utf8, Token/binary>>
                    );

                none ->
                    Req@1
            end,
            Req@3 = case Body of
                {some, Value} ->
                    _pipe@2 = Req@2,
                    _pipe@3 = gleam@http@request:set_header(
                        _pipe@2,
                        <<"content-type"/utf8>>,
                        <<"application/json"/utf8>>
                    ),
                    gleam@http@request:set_body(
                        _pipe@3,
                        gleam@json:to_string(Value)
                    );

                none ->
                    Req@2
            end,
            {ok, Req@3}
    end.

-file("src/shared_auth_client.gleam", 353).
-spec request_json(
    client(),
    gleam@http:method(),
    binary(),
    gleam@option:option(binary()),
    gleam@option:option(gleam@json:json()),
    gleam@dynamic@decode:decoder(ALP)
) -> {ok, ALP} | {error, client_error()}.
request_json(Client, Method, Path, Bearer, Body, Decoder) ->
    gleam@result:'try'(
        build_request(Client, Method, Path, Bearer, Body),
        fun(Req) ->
            gleam@result:'try'(
                send(Client, Req),
                fun(Response) -> decode_json_response(Response, Decoder) end
            )
        end
    ).

-file("src/shared_auth_client.gleam", 101).
?DOC(" Supabase access token to shared-auth access token.\n").
-spec exchange(client(), binary()) -> {ok,
        shared_auth_client@model:exchange_response()} |
    {error, client_error()}.
exchange(Client, Supabase_token) ->
    request_json(
        Client,
        post,
        <<"/auth/exchange"/utf8>>,
        {some, Supabase_token},
        none,
        shared_auth_client@model:exchange_response_decoder()
    ).

-file("src/shared_auth_client.gleam", 116).
?DOC(" RFC-7662-shaped protected introspection.\n").
-spec introspect(client(), binary()) -> {ok,
        shared_auth_client@model:introspection()} |
    {error, client_error()}.
introspect(Client, Token) ->
    case erlang:element(3, Client) of
        none ->
            {error, missing_service_credential};

        {some, Service_credential} ->
            request_json(
                Client,
                post,
                <<"/auth/introspect"/utf8>>,
                {some, Service_credential},
                {some,
                    gleam@json:object(
                        [{<<"token"/utf8>>, gleam@json:string(Token)}]
                    )},
                shared_auth_client@model:introspection_decoder()
            )
    end.

-file("src/shared_auth_client.gleam", 135).
?DOC(" Lightweight bearer verification for gateway auth_request integrations.\n").
-spec verify(client(), binary()) -> {ok, boolean()} | {error, client_error()}.
verify(Client, Token) ->
    gleam@result:'try'(
        build_request(Client, get, <<"/auth/verify"/utf8>>, {some, Token}, none),
        fun(Req) ->
            gleam@result:'try'(
                send(Client, Req),
                fun(Response) -> case erlang:element(2, Response) of
                        200 ->
                            {ok, true};

                        401 ->
                            {ok, false};

                        Status ->
                            {error, {unexpected_status, Status}}
                    end end
            )
        end
    ).

-file("src/shared_auth_client.gleam", 151).
-spec jwks(client()) -> {ok, shared_auth_client@model:jwks()} |
    {error, client_error()}.
jwks(Client) ->
    request_json(
        Client,
        get,
        <<"/.well-known/jwks.json"/utf8>>,
        none,
        none,
        shared_auth_client@model:jwks_decoder()
    ).

-file("src/shared_auth_client.gleam", 162).
-spec capabilities(client()) -> {ok, shared_auth_client@model:capabilities()} |
    {error, client_error()}.
capabilities(Client) ->
    request_json(
        Client,
        get,
        <<"/auth/capabilities"/utf8>>,
        none,
        none,
        shared_auth_client@model:capabilities_decoder()
    ).

-file("src/shared_auth_client.gleam", 173).
-spec factors(client(), binary()) -> {ok,
        list(shared_auth_client@model:factor())} |
    {error, client_error()}.
factors(Client, Access_token) ->
    request_json(
        Client,
        get,
        <<"/auth/factors"/utf8>>,
        {some, Access_token},
        none,
        gleam@dynamic@decode:list(shared_auth_client@model:factor_decoder())
    ).

-file("src/shared_auth_client.gleam", 459).
-spec optional_string_field(binary(), gleam@option:option(binary())) -> list({binary(),
    gleam@json:json()}).
optional_string_field(Name, Value) ->
    case Value of
        {some, Value@1} ->
            case begin
                _pipe = Value@1,
                _pipe@1 = gleam@string:trim(_pipe),
                gleam@string:to_option(_pipe@1)
            end of
                {some, Value@2} ->
                    [{Name, gleam@json:string(Value@2)}];

                none ->
                    []
            end;

        none ->
            []
    end.

-file("src/shared_auth_client.gleam", 187).
-spec enroll_totp(client(), binary(), gleam@option:option(binary())) -> {ok,
        shared_auth_client@model:totp_enrollment()} |
    {error, client_error()}.
enroll_totp(Client, Access_token, Label) ->
    request_json(
        Client,
        post,
        <<"/auth/factors/totp/enroll"/utf8>>,
        {some, Access_token},
        {some,
            gleam@json:object(optional_string_field(<<"label"/utf8>>, Label))},
        shared_auth_client@model:totp_enrollment_decoder()
    ).

-file("src/shared_auth_client.gleam", 202).
-spec confirm_totp(client(), binary(), binary(), binary()) -> {ok,
        shared_auth_client@model:step_up_response()} |
    {error, client_error()}.
confirm_totp(Client, Access_token, Factor_id, Code) ->
    request_json(
        Client,
        post,
        <<"/auth/factors/totp/confirm"/utf8>>,
        {some, Access_token},
        {some,
            gleam@json:object(
                [{<<"factor_id"/utf8>>, gleam@json:string(Factor_id)},
                    {<<"code"/utf8>>, gleam@json:string(Code)}]
            )},
        shared_auth_client@model:step_up_response_decoder()
    ).

-file("src/shared_auth_client.gleam", 366).
-spec request_empty(
    client(),
    gleam@http:method(),
    binary(),
    gleam@option:option(binary()),
    gleam@option:option(gleam@json:json())
) -> {ok, nil} | {error, client_error()}.
request_empty(Client, Method, Path, Bearer, Body) ->
    gleam@result:'try'(
        build_request(Client, Method, Path, Bearer, Body),
        fun(Req) ->
            gleam@result:'try'(
                send(Client, Req),
                fun(Response) -> case erlang:element(2, Response) of
                        401 ->
                            {error, unauthorized};

                        Status ->
                            case is_success(Status) of
                                true ->
                                    {ok, nil};

                                false ->
                                    {error, {unexpected_status, Status}}
                            end
                    end end
            )
        end
    ).

-file("src/shared_auth_client.gleam", 223).
-spec delete_factor(client(), binary(), binary()) -> {ok, nil} |
    {error, client_error()}.
delete_factor(Client, Access_token, Factor_id) ->
    Path = <<"/auth/factors/"/utf8,
        (gleam_stdlib:percent_encode(Factor_id))/binary>>,
    request_empty(Client, delete, Path, {some, Access_token}, none).

-file("src/shared_auth_client.gleam", 232).
-spec create_challenge(
    client(),
    binary(),
    shared_auth_client@model:challenge_kind()
) -> {ok, shared_auth_client@model:challenge_start()} | {error, client_error()}.
create_challenge(Client, Access_token, Kind) ->
    request_json(
        Client,
        post,
        <<"/auth/challenges"/utf8>>,
        {some, Access_token},
        {some,
            gleam@json:object(
                [{<<"kind"/utf8>>,
                        begin
                            _pipe = Kind,
                            _pipe@1 = shared_auth_client@model:challenge_kind_to_string(
                                _pipe
                            ),
                            gleam@json:string(_pipe@1)
                        end}]
            )},
        shared_auth_client@model:challenge_start_decoder()
    ).

-file("src/shared_auth_client.gleam", 251).
-spec verify_challenge(client(), binary(), binary(), binary()) -> {ok,
        shared_auth_client@model:step_up_response()} |
    {error, client_error()}.
verify_challenge(Client, Access_token, Challenge_id, Code) ->
    Path = <<<<"/auth/challenges/"/utf8,
            (gleam_stdlib:percent_encode(Challenge_id))/binary>>/binary,
        "/verify"/utf8>>,
    request_json(
        Client,
        post,
        Path,
        {some, Access_token},
        {some, gleam@json:object([{<<"code"/utf8>>, gleam@json:string(Code)}])},
        shared_auth_client@model:step_up_response_decoder()
    ).

-file("src/shared_auth_client.gleam", 269).
-spec start_passkey_registration(
    client(),
    binary(),
    gleam@option:option(binary())
) -> {ok, shared_auth_client@model:ceremony_start()} | {error, client_error()}.
start_passkey_registration(Client, Access_token, Label) ->
    request_json(
        Client,
        post,
        <<"/auth/passkeys/registration/options"/utf8>>,
        {some, Access_token},
        {some,
            gleam@json:object(optional_string_field(<<"label"/utf8>>, Label))},
        shared_auth_client@model:ceremony_start_decoder()
    ).

-file("src/shared_auth_client.gleam", 284).
-spec finish_passkey_registration(
    client(),
    binary(),
    binary(),
    gleam@json:json(),
    gleam@option:option(binary())
) -> {ok, shared_auth_client@model:factor()} | {error, client_error()}.
finish_passkey_registration(
    Client,
    Access_token,
    Challenge_id,
    Credential,
    Label
) ->
    Fields = begin
        _pipe = [{<<"challenge_id"/utf8>>, gleam@json:string(Challenge_id)},
            {<<"credential"/utf8>>, Credential}],
        lists:append(_pipe, optional_string_field(<<"label"/utf8>>, Label))
    end,
    request_json(
        Client,
        post,
        <<"/auth/passkeys/registration/verify"/utf8>>,
        {some, Access_token},
        {some, gleam@json:object(Fields)},
        shared_auth_client@model:factor_decoder()
    ).

-file("src/shared_auth_client.gleam", 308).
-spec start_passkey_authentication(client(), binary()) -> {ok,
        shared_auth_client@model:ceremony_start()} |
    {error, client_error()}.
start_passkey_authentication(Client, Access_token) ->
    request_json(
        Client,
        post,
        <<"/auth/passkeys/authentication/options"/utf8>>,
        {some, Access_token},
        {some, gleam@json:object([])},
        shared_auth_client@model:ceremony_start_decoder()
    ).

-file("src/shared_auth_client.gleam", 322).
-spec finish_passkey_authentication(
    client(),
    binary(),
    binary(),
    gleam@json:json()
) -> {ok, shared_auth_client@model:step_up_response()} | {error, client_error()}.
finish_passkey_authentication(Client, Access_token, Challenge_id, Credential) ->
    request_json(
        Client,
        post,
        <<"/auth/passkeys/authentication/verify"/utf8>>,
        {some, Access_token},
        {some,
            gleam@json:object(
                [{<<"challenge_id"/utf8>>, gleam@json:string(Challenge_id)},
                    {<<"credential"/utf8>>, Credential}]
            )},
        shared_auth_client@model:step_up_response_decoder()
    ).
