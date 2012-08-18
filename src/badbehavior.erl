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

% These are here for functions that have not been called yet to make the compiler happy.
-export([httpbl/4]).

%% @doc Determines whether the HTTP request should be allowed.
%% @end
%% @spec check_request(Request :: any(), OptList :: any()) ->
%%	ok | {error, Reason :: term()} | {blocked, Reason :: term()}
-spec check_request(Request :: any(), OptList :: any()) ->
	ok | {error, Reason :: term()} | {blocked, Reason :: term()}.

check_request(_Request, _OptList) ->
	{error, not_implemented}.

% Each of the sub-functions will return one of several values:
% ok -> request has been determined to be ok
% {blocked, Reason} -> request should be blocked with reason Reason
% continue -> not enough info to decide yet; keep running checks against the request

%% @doc Checks the request against http:BL.
%% @end
% TODO: Write spec
httpbl(IP, ApiKey, MinimumThreatRating, MaxAge) ->
	case httpbl:lookup(IP, ApiKey) of
		false -> continue;
		{search_engine, _} -> ok; % search engines are whitelisted
		{found, ThreatRating, _Types=[_|_], Age} when ThreatRating >= MinimumThreatRating, Age =< MaxAge ->
			{blocked, blacklist_httpbl};
		{found, _, _, _} -> continue
	end.
