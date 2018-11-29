%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% Copyright (c) 2007-2017 Pivotal Software, Inc.  All rights reserved.
%%

-module(rabbit_trust_store).

%% Transitional step until we can require Erlang/OTP 21 and
%% use the now recommended try/catch syntax for obtaining the stack trace.
-compile(nowarn_deprecated_function).

-behaviour(gen_server).

-export([mode/0, refresh/0, list/0]). %% Console Interface.
-export([validate/3, is_allowed/2, is_allowed/1]). %% Client-side Interface.
-export([start_link/0]).
-export([init/1, terminate/2,
         handle_call/3, handle_cast/2,
         handle_info/2,
         code_change/3]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/public_key.hrl").

-type certificate() :: #'OTPCertificate'{}.
-type event()       :: valid_peer
                     | valid
                     | {bad_cert, Other :: atom()
                                | unknown_ca
                                | selfsigned_peer}
                     | {extension, #'Extension'{}}.
-type state()       :: confirmed | continue.
-type outcome()     :: {valid, state()}
                     | {fail, Reason :: term()}
                     | {unknown, state()}.
-type issuer_id()   :: {{integer(), [#'AttributeTypeAndValue'{}]}, integer()}.
-type operation()   :: 'whitelist'
                     | 'blacklist'.

-define(APP,                          rabbitmq_trust_store).
-define(TRUST_STORE_TAB,              trust_store_t).
-define(DEFAULT_REFRESH_INTERVAL,     30).
-define(OPERATION,                    rabbit_misc:get_env(?APP, operation, whitelist)).

-record(state, {
    providers_state :: [{module(), term()}],
    refresh_interval :: integer()
}).
-record(entry, {
    name :: string(),
    cert_id :: term(),
    provider :: module(),
    issuer_id :: tuple(),
    certificate :: public_key:der_encoded()
}).


%% OTP Supervision

start_link() ->
    gen_server:start_link({local, trust_store}, ?MODULE, [], []).


%% Console Interface

-spec mode() -> 'automatic' | 'manual'.
mode() ->
    gen_server:call(trust_store, mode).

-spec refresh() -> integer().
refresh() ->
    gen_server:call(trust_store, refresh).

-spec list() -> string().
list() ->
    Formatted = lists:map(
        fun(#entry{
                name = N,
                cert_id = CertId,
                certificate = Cert,
                issuer_id = {_, Serial}}) ->
            %% Use the certificate unique identifier as a default for the name.
            Name = case N of
                undefined -> io_lib:format("~p", [CertId]);
                _         -> N
            end,
            Validity = rabbit_ssl:peer_cert_validity(Cert),
            Subject = rabbit_ssl:peer_cert_subject(Cert),
            Issuer = rabbit_ssl:peer_cert_issuer(Cert),
            Text = io_lib:format("Name: ~s~nSerial: ~p | 0x~.16.0B~n"
                                 "Subject: ~s~nIssuer: ~s~nValidity: ~p~n",
                                 [Name, Serial, Serial,
                                  Subject, Issuer, Validity]),
            lists:flatten(Text)
        end,
        ets:tab2list(?TRUST_STORE_TAB)),
    string:join(Formatted, "~n~n").

%% Client (SSL Socket) Interface

-spec validate(certificate(), event(), state()) -> outcome().
validate(C, {bad_cert, unknown_ca}, confirmed) ->
    ErrMsg = "Certificate badly formatted",
    rabbit_log:warning(ErrMsg ++ ": ~p", [C]),
    {fail, ErrMsg};
validate(#'OTPCertificate'{}=C, {bad_cert, unknown_ca}, continue) ->
    case is_allowed(C, OP = ?OPERATION) of
        true ->
            {valid, confirmed};
        false ->
            {fail, "CA not known AND certificate is " ++ op_fmt(OP)}
    end;
validate(#'OTPCertificate'{}=C, {bad_cert, selfsigned_peer}, continue) ->
    case is_allowed(C, OP = ?OPERATION) of
        true ->
            {valid, confirmed};
        false ->
            {fail, "certificate is " ++ op_fmt(OP)}
    end;
validate(_, {bad_cert, _} = Reason, _) ->
    {fail, Reason};
validate(_, valid, St) ->
    {valid, St};
validate(#'OTPCertificate'{}=_, valid_peer, St) ->
    {valid, St};
validate(_, {extension, _}, St) ->
    {unknown, St}.

-spec is_allowed(certificate(), operation()) -> boolean().
is_allowed(C, 'whitelist') -> is_allowed(C);
is_allowed(C, 'blacklist') -> not is_allowed(C).

-spec is_allowed(certificate()) -> boolean().
is_allowed(C) -> ets:member(?TRUST_STORE_TAB, extract_issuer_id(C)).

%% Generic Server Callbacks

init([]) ->
    erlang:process_flag(trap_exit, true),
    ets:new(?TRUST_STORE_TAB, [protected,
                               named_table,
                               set,
                               {keypos, #entry.issuer_id}]),
    Config = application:get_all_env(rabbitmq_trust_store),
    ProvidersState = refresh_certs(Config, []),
    Interval = refresh_interval(Config),
    if
        Interval =< 0 -> ok;
        true          -> erlang:send_after(Interval, erlang:self(), refresh)
    end,
    {ok,
     #state{
      providers_state = ProvidersState,
      refresh_interval = Interval}}.

handle_call(mode, _, St) ->
    {reply, mode(St), St};
handle_call(refresh, _, #state{providers_state = ProvidersState} = St) ->
    Config = application:get_all_env(rabbitmq_trust_store),
    NewProvidersState = refresh_certs(Config, ProvidersState),
    {reply, ok, St#state{providers_state = NewProvidersState}};
handle_call(_, _, St) ->
    {noreply, St}.

handle_cast(_, St) ->
    {noreply, St}.

handle_info(refresh, #state{refresh_interval = Interval,
                            providers_state = ProvidersState} = St) ->
    Config = application:get_all_env(rabbitmq_trust_store),
    NewProvidersState = refresh_certs(Config, ProvidersState),
    erlang:send_after(Interval, erlang:self(), refresh),
    {noreply, St#state{providers_state = NewProvidersState}};
handle_info(_, St) ->
    {noreply, St}.

terminate(shutdown, _St) ->
    true = ets:delete(?TRUST_STORE_TAB).

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% Ancillary & Constants

mode(#state{refresh_interval = I}) ->
    if
        I =< 0  -> 'manual';
        true    -> 'automatic'
    end.

refresh_interval(Config) ->
    Seconds = case proplists:get_value(refresh_interval, Config) of
        undefined ->
            ?DEFAULT_REFRESH_INTERVAL;
        S when is_integer(S), S >= 0 ->
            S;
        {seconds, S} when is_integer(S), S >= 0 ->
            S
    end,
    timer:seconds(Seconds).

%% =================================

-spec refresh_certs(Config, State) -> State
      when State :: [{module(), term()}],
           Config :: list().
refresh_certs(Config, State) ->
    Providers = providers(Config),
    clean_deleted_providers(Providers),
    lists:foldl(
        fun(Provider, NewStates) ->
            ProviderState = proplists:get_value(Provider, State, nostate),
            RefreshedState = refresh_provider_certs(Provider, Config, ProviderState),
            [{Provider, RefreshedState} | NewStates]
        end,
        [],
        Providers).

-spec refresh_provider_certs(Provider, Config, ProviderState) -> ProviderState
      when Provider :: module(),
           Config :: list(),
           ProviderState :: term().
refresh_provider_certs(Provider, Config, ProviderState) ->
    case list_certs(Provider, Config, ProviderState) of
        no_change ->
            ProviderState;
        {ok, CertsList, NewProviderState} ->
            update_certs(CertsList, Provider, Config),
            NewProviderState;
        {error, Reason} ->
            rabbit_log:error("Unable to load certificate list for provider ~p,"
                             " reason: ~p~n",
                             [Provider, Reason]),
            ProviderState
    end.

list_certs(Provider, Config, nostate) ->
    Provider:list_certs(Config);
list_certs(Provider, Config, ProviderState) ->
    Provider:list_certs(Config, ProviderState).

update_certs(CertsList, Provider, Config) ->
    OldCertIds = get_old_cert_ids(Provider),
    {NewCertIds, _} = lists:unzip(CertsList),

    lists:foreach(
        fun(CertId) ->
            Attributes = proplists:get_value(CertId, CertsList),
            Name = proplists:get_value(name, Attributes, undefined),
            case load_and_decode_cert(Provider, CertId, Attributes, Config) of
                {ok, Cert, IssuerId} ->
                    save_cert(CertId, Provider, IssuerId, Cert, Name);
                {error, Reason} ->
                    rabbit_log:error("Unable to load CA certificate ~p"
                                     " with provider ~p,"
                                     " reason: ~p",
                                     [CertId, Provider, Reason])
            end
        end,
        NewCertIds -- OldCertIds),
    lists:foreach(
        fun(CertId) ->
            delete_cert(CertId, Provider)
        end,
        OldCertIds -- NewCertIds),
    ok.

load_and_decode_cert(Provider, CertId, Attributes, Config) ->
    try
        Provider:load_cert(CertId, Attributes, Config)
    of
	{ok, Cert} ->
	    DecodedCert = public_key:pkix_decode_cert(Cert, otp),
	    Id = extract_issuer_id(DecodedCert),
	    {ok, Cert, Id};
	{error, Reason} -> {error, Reason}
    catch _:Error ->
        {error, {Error, erlang:get_stacktrace()}}
    end.

delete_cert(CertId, Provider) ->
    MS = ets:fun2ms(fun(#entry{cert_id = CId, provider = P})
                    when P == Provider, CId == CertId ->
                        true
                    end),
    ets:select_delete(?TRUST_STORE_TAB, MS).

save_cert(CertId, Provider, Id, Cert, Name) ->
    ets:insert(?TRUST_STORE_TAB, #entry{cert_id     = CertId,
                                        provider    = Provider,
                                        issuer_id   = Id,
                                        certificate = Cert,
                                        name        = Name}).

get_old_cert_ids(Provider) ->
    MS = ets:fun2ms(fun(#entry{provider = P, cert_id = CId})
                    when P == Provider ->
                        CId
                    end),
    ets:select(?TRUST_STORE_TAB, MS).

providers(Config) ->
    Providers = proplists:get_value(providers, Config, []),
    lists:filter(
        fun(Provider) ->
            case code:ensure_loaded(Provider) of
                {module, Provider} -> true;
                {error, Error} ->
                    rabbit_log:warning("Unable to load trust store certificates"
                                       " with provider module ~p. Reason: ~p~n",
                                       [Provider, Error]),
                    false
            end
        end,
        Providers).

extract_issuer_id(#'OTPCertificate'{} = C) ->
    {Serial, Issuer} = case public_key:pkix_issuer_id(C, other) of
        {error, _Reason} ->
            {ok, Identifier} = public_key:pkix_issuer_id(C, self),
            Identifier;
        {ok, Identifier} ->
            Identifier
    end,
    {Issuer, Serial}.

clean_deleted_providers(Providers) ->
    [{EntryMatch, _, [true]}] =
        ets:fun2ms(fun(#entry{provider = P})-> true end),
    Condition = [ {'=/=', '$1', Provider} || Provider <- Providers ],
    ets:select_delete(?TRUST_STORE_TAB, [{EntryMatch, Condition, [true]}]).

op_fmt('whitelist')      -> "not whitelisted";
op_fmt('blacklist')      -> "blacklisted".
