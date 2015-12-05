%% Copyright (C) 2015 Jonas Boberg
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

-module(ex_apns_packet).

%%% API
-export([notification/5,
         parse_errors/1]).

%%% Macros

-define(SEND_COMMAND, 2).
-define(ITEM_ID_LENGTH, 1).
-define(ITEM_DATA_LENGTH, 2).

-define(ITEM_ID_DEVICE_TOKEN, 1).
-define(DEVICE_TOKEN_LENGTH, 32).

-define(ITEM_ID_PAYLOAD, 2).

-define(ITEM_ID_IDENTIFIER, 3).
-define(IDENTIFIER_LENGTH, 4).

-define(ITEM_ID_EXPIRATION_DATE, 4).
-define(EXPIRATION_DATE_LENGTH, 4).

-define(ITEM_ID_PRIORITY, 5).
-define(PRIORITY_LENGTH, 1).

-define(FRAME_LENGTH(PayloadLength),
        (?ITEM_ID_LENGTH + ?ITEM_DATA_LENGTH) * 5 +
            ?DEVICE_TOKEN_LENGTH +
            PayloadLength +
            ?IDENTIFIER_LENGTH +
            ?EXPIRATION_DATE_LENGTH +
            ?PRIORITY_LENGTH).

-define(ERROR_COMMAND, 8).

%%%====================================================================
%%% API
%%%====================================================================

-spec notification(binary(), iolist(), integer(), integer(), integer()) -> iolist().
notification(DeviceToken, Payload, Identifier, Expiry, Priority) ->
    PayloadLength = iolist_size(Payload),
    FrameLength = ?FRAME_LENGTH(PayloadLength),
    [<<?SEND_COMMAND:8,
       FrameLength:32/integer-big,
       %% Frame data
       ?ITEM_ID_DEVICE_TOKEN:8,
       ?DEVICE_TOKEN_LENGTH:16/integer-big,
       DeviceToken:?DEVICE_TOKEN_LENGTH/binary,
       ?ITEM_ID_IDENTIFIER,
       ?IDENTIFIER_LENGTH:16/integer-big,
       Identifier:(?IDENTIFIER_LENGTH*8)/integer-big,
       ?ITEM_ID_EXPIRATION_DATE:8,
       ?EXPIRATION_DATE_LENGTH:16/integer-big,
       Expiry:(?EXPIRATION_DATE_LENGTH*8)/integer-big,
       ?ITEM_ID_PRIORITY:8,
       ?PRIORITY_LENGTH:16/integer-big,
       Priority:8,
       ?ITEM_ID_PAYLOAD:8,
       PayloadLength:16/integer-big>>,
     Payload].


-spec parse_errors(binary()) -> {[{Reason :: atom(), Identifier :: integer()}], Rest :: binary()}.
parse_errors(Bin) ->
    parse_errors1(Bin, []).

parse_errors1(<<?ERROR_COMMAND:8, Status:8, Identifier:32/integer-big, Rest/binary>>, Acc) ->
    parse_errors1(Rest, [{status_to_atom(Status), Identifier}|Acc]);
parse_errors1(Bin, Acc) when byte_size(Bin) >= 6 ->
    {lists:reverse(Acc), <<>>};
parse_errors1(Rest, Acc) ->
    {lists:reverse(Acc), Rest}.


%%%====================================================================
%%% Private
%%%====================================================================

status_to_atom(0) ->
    no_error;
status_to_atom(1) ->
    processing_error;
status_to_atom(2) ->
    missing_device_token;
status_to_atom(3) ->
    missing_topic;
status_to_atom(4) ->
    missing_payload;
status_to_atom(5) ->
    invalid_token_size;
status_to_atom(6) ->
    invalid_topic_size;
status_to_atom(7) ->
    invalid_payload_size;
status_to_atom(8) ->
    invalid_token;
status_to_atom(10) ->
    shutdown;
status_to_atom(255) ->
    unknown;
status_to_atom(_) ->
    unknown.
