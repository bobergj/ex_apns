%% Copyright (c) 2012, Anthony Ramine <n.oxyde@gmail.com>
%%
%% Copyright (C) 2015 Jonas Boberg
%% - Extended version using modern APNS format and new API.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(ex_apns).
-behaviour(gen_server).

-export([start/0,
         start/3,
         stop/1,
         start_link/3,
         send/5]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%% Records
-record(state, {env, certfile, socket, next = 0, error_acc = <<>>}).


%% @equiv application:start(ex_apns)
start() ->
    ssl:start(),
    application:start(ex_apns).

%% @spec start(atom(), env(), string()) -> {ok, Pid} | start_error()
%% @doc Create an ex_apns process.
%%      The resulting process will be locally registered as `Name'.
start(Name, Env, CertFile) ->
    ex_apns_sup:start_child(Name, Env, CertFile).

%% @doc stop(server_ref()) -> stopped.
stop(ServerRef) ->
    gen_server:call(ServerRef, stop, infinity).

%% @spec start_link(atom(), env(), string()) -> {ok, Pid} | start_error()
%% @doc Create an ex_apns process as part of a supervision tree.
%%      The resulting process will be locally registered as `Name'.
start_link(Name, Env, CertFile) ->
    gen_server:start_link({local, Name}, ?MODULE, {Env, CertFile},
                          [{timeout, infinity}]).

%% @spec send(server_ref(), token(), payload()) -> ok
%% @doc Send a notification.
send(ServerRef, DeviceToken, Payload, Expiry, Priority)
  when is_binary(DeviceToken), byte_size(DeviceToken) == 32,
       is_integer(Expiry),
       (Priority == 5 orelse Priority == 10) ->
    PayloadBin = jsx:encode(Payload),
    gen_server:cast(ServerRef, {send, DeviceToken, PayloadBin, Expiry, Priority}).


%% @hidden
init({Env, CertFile}) ->
    case connect(env_to_gateway(Env), 2195, CertFile) of
        {ok, Socket} ->
            {ok, #state{env = Env, certfile = CertFile, socket = Socket}};
        {error, Reason} ->
            log_connection_error(Reason),
            {stop, Reason}
    end.

%% @hidden
handle_call(stop, _From, State) ->
    {stop, normal, stopped, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%% @hidden
handle_cast({send, DeviceToken, Payload, Expiry, Priority}, State = #state{next = Id}) ->
    Packet = ex_apns_packet:notification(DeviceToken, Payload, Id, Expiry, Priority),
    send(Packet, State#state{next = Id + 1});
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @hidden
handle_info({ssl, Socket, Data}, State = #state{socket = Socket, error_acc = DataAcc}) ->
    ssl:setopts(Socket, [{active, once}]),
    AllData = <<DataAcc/binary, Data/binary>>,
    {Errors, Rest} = ex_apns_packet:parse_errors(AllData),
    handle_errors(Errors, State#state{error_acc = Rest});
handle_info({tcp_close, Socket}, State = #state{socket = Socket}) ->
    {noreply, State#state{socket = undefined}};
handle_info(_Msg, State) ->
    {noreply, State}.


%% @hidden
terminate(_Reason, _State) ->
    ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% @spec connect(address(), integer(), string()) -> result()
%%       where address() = string() | atom() | inet:ip_address()
%%             result() = {ok, ssl:socket()} | {error, inet:posix()}
connect(Address, Port, CertFile) ->
    CaCertFile = filename:join([code:priv_dir(?MODULE), "entrust_2048_ca.cer"]),
    SslOptions = [binary,
                  {active, once},
                  {certfile, CertFile},
                  {cacertfile, CaCertFile},
                  %% Do not use TLS v2 due to Erlang bug, but support v1 as production server may use that.
                  {versions,['tlsv1.1', 'tlsv1']}],
    ssl:connect(Address, Port, SslOptions).

%% @spec connect(State::#state{}) -> {ok, #state{}} | {stop, reason()}
%%       where reason() = closed | inet:posix()
connect(#state{env = Env, certfile = CertFile}) ->
    connect(env_to_gateway(Env), 2195, CertFile).


%% @spec send(iodata(), #state{}) -> {noreply, #state{}} | {stop, reason()}
%%       where reason() = closed | inet:posix()
send(Packet, State = #state{socket = undefined}) ->
    case connect(State) of
        {ok, NewSocket} ->
            send(Packet, State#state{socket = NewSocket});
        {error, Reason} ->
            log_connection_error(Reason),
            {noreply, State}
    end;
send(Packet, State = #state{socket = Socket}) ->
    case ssl:send(Socket, Packet) of
        ok ->
            {noreply, State};
        {error, closed} ->
            log_send_error(closed),
            ssl:close(Socket),
            send(Packet, State#state{socket = undefined});
        {error, Reason} ->
            log_send_error(Reason),
            ssl:close(Socket),
            {noreply, State#state{socket = undefined}}
    end.


handle_errors([{no_error, _}|T], State) ->
    handle_errors(T, State);
handle_errors([{shutdown, _}=Error| T], State = #state{socket = Socket}) ->
    log_notification_error_resonse(Error),
    catch ssl:close(Socket),
    handle_errors(T, State#state{socket = undefined});
handle_errors([Error|T], State) ->
    log_notification_error_resonse(Error),
    handle_errors(T, State);
handle_errors([], State) ->
    {noreply, State}.


%% @spec name() -> atom()
name() ->
    {registered_name, Name} = process_info(self(), registered_name),
    Name.

%% @spec env_to_gateway(Env::env()) -> atom()
env_to_gateway(production) ->
    'gateway.push.apple.com';
env_to_gateway(sandbox) ->
    'gateway.sandbox.push.apple.com'.


log_send_error(Reason) ->
    Format = "~w[~w]: could not send extended notification (~w)~n",
    error_logger:error_msg(Format, [?MODULE, name(), Reason]).


log_connection_error(Reason) ->
    Format = "~w[~w]: could connect to APNs server (~w)~n",
    error_logger:error_msg(Format, [?MODULE, name(), Reason]).


log_notification_error_resonse({Status, Identifier}) ->
    Format = "~w[~w]: could not send extended notification ~B (~w)~n",
    error_logger:error_msg(Format, [?MODULE, name(), Identifier, Status]).
