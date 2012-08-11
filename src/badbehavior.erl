%--------------------------------------------------------------------------
%% @author David K. Jones [http://www.tadmas.com/]
%% @reference This is a port of the
%% <a href="http://www.bad-behavior.ioerror.us/">original PHP version</a>
%% written by Michael Hampton.
%% @version 2.2.7
%% @doc Detects and blocks unwanted Web accesses
%% @end
%--------------------------------------------------------------------------
-module(badbehavior).

-export([check_request/2]).

%% @doc Determines whether the HTTP request should be allowed.
%% @end
%% @spec check_request(Request :: any(), OptList :: any()) ->
%%	ok | {error, Reason :: term()} | {blocked, Reason :: term()}
-spec check_request(Request :: any(), OptList :: any()) ->
	ok | {error, Reason :: term()} | {blocked, Reason :: term()}.

check_request(_Request, _OptList) ->
	{error, not_implemented}.
