%--------------------------------------------------------------------------
%% @author David K. Jones [http://www.tadmas.com/]
%% @doc Checks an IP address against the HTTP Blacklist.
%% @end
%--------------------------------------------------------------------------
-module(httpbl).

-include_lib("kernel/include/inet.hrl").

-export([lookup/2]).

% edoc on R14B doesn't like 0..255 notation.
%% @type threat_rating() =  integer().
%% The threat rating is on a logarithmic scale.  A rating of 25 is the equivalent
%% of sending 100 spam messages to a honey pot trap, a rating of 50 is equivalent
%% to sending 10,000 message, 75 is equivalent to 1,000,000, etc.
-type    threat_rating() :: 0..255.

%% @doc Looks up a visitor IP Address in the HTTP blacklist.
%% @spec lookup(IP :: inet:ip_address(), ApiKey :: string()) ->
%%            false | {search_engine, search_engine()} |
%%            {found, threat_rating(), [visitor_type()], Days :: integer()}
-spec    lookup(IP :: inet:ip_address(), ApiKey :: string()) ->
              false | {search_engine, search_engine()} |
              {found, threat_rating(), [visitor_type()], Days :: integer()}.

lookup(_IP, []) ->
	false;
lookup(_IPv6={_,_,_,_,_,_,_,_}, _ApiKey) ->
	false;
lookup(_IPv4={A,B,C,D}, ApiKey) ->
	DnsName = [ApiKey, ".",
		integer_to_list(D), ".",
		integer_to_list(C), ".",
		integer_to_list(B), ".",
		integer_to_list(A), ".dnsbl.httpbl.org"],
	case inet:gethostbyname(DnsName, inet) of
		{error, _} ->
			false;
		{ok, #hostent{h_addrtype=inet, h_addr_list = [{127,_,N,0}|_]}} ->
			{search_engine, search_engine_type(N)};
		{ok, #hostent{h_addrtype=inet, h_addr_list = [{127,Days,Threat,Type}|_]}} ->
			{found, Threat, visitor_types(Type), Days}
	end.

%% @type visitor_type() =  suspicious | harvester | comment_spammer.
-type    visitor_type() :: suspicious | harvester | comment_spammer.

%% @doc Decodes the visitor type information contained in the http:BL response.
%% @spec visitor_types(N :: integer()) -> [visitor_type()]
-spec    visitor_types(N :: integer()) -> [visitor_type()].

visitor_types(N) when N >= 8 -> visitor_types(N band 7);
visitor_types(N) -> visitor_types(N, []).

visitor_types(N, Acc) when N >= 4 -> visitor_types(N - 4, [comment_spammer | Acc]);
visitor_types(N, Acc) when N >= 2 -> visitor_types(N - 2, [harvester | Acc]);
visitor_types(1, Acc) -> [suspicious | Acc];
visitor_types(0, Acc) -> Acc.

%% @type search_engine() =  unknown | altavista | ask | baidu | excite | google |
%%                          looksmart | lycos | msn | yahoo | cuil | infoseek | misc.
-type    search_engine() :: unknown | altavista | ask | baidu | excite | google |
                            looksmart | lycos | msn | yahoo | cuil | infoseek | misc.

%% @doc Decodes the search engine information contained in the http:BL response.
%% @spec search_engine_type(Number :: integer()) -> search_engine()
-spec    search_engine_type(Number :: integer()) -> search_engine().

search_engine_type(0) -> unknown;
search_engine_type(1) -> altavista;
search_engine_type(2) -> ask;
search_engine_type(3) -> baidu;
search_engine_type(4) -> excite;
search_engine_type(5) -> google;
search_engine_type(6) -> looksmart;
search_engine_type(7) -> lycos;
search_engine_type(8) -> msn;
search_engine_type(9) -> yahoo;
search_engine_type(10) -> cuil;
search_engine_type(11) -> infoseek;
search_engine_type(12) -> misc;
search_engine_type(_) -> unknown.