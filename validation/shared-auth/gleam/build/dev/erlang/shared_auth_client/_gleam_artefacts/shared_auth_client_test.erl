-module(shared_auth_client_test).
-compile([no_auto_import, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-define(FILEPATH, "test/shared_auth_client_test.gleam").
-export([main/0, protected_introspection_requires_service_credential_test/0]).

-file("test/shared_auth_client_test.gleam", 4).
-spec main() -> nil.
main() ->
    gleeunit:main().

-file("test/shared_auth_client_test.gleam", 8).
-spec protected_introspection_requires_service_credential_test() -> nil.
protected_introspection_requires_service_credential_test() ->
    Client@1 = case shared_auth_client:new(
        <<"https://gateway.example/shared-auth"/utf8>>
    ) of
        {ok, Client} -> Client;
        _assert_fail ->
            erlang:error(#{gleam_error => let_assert,
                        message => <<"Pattern match failed, no pattern matched the value."/utf8>>,
                        file => <<?FILEPATH/utf8>>,
                        module => <<"shared_auth_client_test"/utf8>>,
                        function => <<"protected_introspection_requires_service_credential_test"/utf8>>,
                        line => 9,
                        value => _assert_fail,
                        start => 150,
                        'end' => 239,
                        pattern_start => 161,
                        pattern_end => 171})
    end,
    _assert_subject = shared_auth_client:introspect(
        Client@1,
        <<"ore-token"/utf8>>
    ),
    _assert_subject@1 = {error, missing_service_credential},
    case _assert_subject =:= _assert_subject@1 of
        true -> nil;
        false -> erlang:error(#{gleam_error => assert,
                message => <<"Assertion failed."/utf8>>,
                file => <<?FILEPATH/utf8>>,
                module => <<"shared_auth_client_test"/utf8>>,
                function => <<"protected_introspection_requires_service_credential_test"/utf8>>,
                line => 11,
                kind => binary_operator,
                operator => '==',
                left => #{kind => expression,
                    value => _assert_subject,
                    start => 249,
                    'end' => 299
                    },
                right => #{kind => expression,
                    value => _assert_subject@1,
                    start => 307,
                    'end' => 357
                    },
                start => 242,
                'end' => 357,
                expression_start => 249})
    end,
    Client@2 = begin
        _pipe = Client@1,
        _pipe@1 = shared_auth_client:with_service_credential(
            _pipe,
            <<"service-secret"/utf8>>
        ),
        shared_auth_client:without_service_credential(_pipe@1)
    end,
    _assert_subject@2 = shared_auth_client:introspect(
        Client@2,
        <<"ore-token"/utf8>>
    ),
    _assert_subject@3 = {error, missing_service_credential},
    case _assert_subject@2 =:= _assert_subject@3 of
        true -> nil;
        false -> erlang:error(#{gleam_error => assert,
                message => <<"Assertion failed."/utf8>>,
                file => <<?FILEPATH/utf8>>,
                module => <<"shared_auth_client_test"/utf8>>,
                function => <<"protected_introspection_requires_service_credential_test"/utf8>>,
                line => 18,
                kind => binary_operator,
                operator => '==',
                left => #{kind => expression,
                    value => _assert_subject@2,
                    start => 515,
                    'end' => 565
                    },
                right => #{kind => expression,
                    value => _assert_subject@3,
                    start => 573,
                    'end' => 623
                    },
                start => 508,
                'end' => 623,
                expression_start => 515})
    end.
