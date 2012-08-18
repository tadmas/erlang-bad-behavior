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
-export([make_subnet/2]).

% These are here for functions that have not been called yet to make the compiler happy.
-export([httpbl/4,is_ipv4_in_subnet_list/2,ipv4_subnet_match/2]).

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

%--------------------------------------------------------------------------
% IP ADDRESS UTILITY FUNCTIONS
%--------------------------------------------------------------------------

%% @type ip4_subnet() =  bitstring().
%% <p>IPv4 subnet mask.
%% The size of the bitstring determines the subnet size, and the contents of the bitstring are the
%% most-significant bits in the subnet mask.  For example, the private subnet 172.16.0.0/12 would be
%% specified as <code>&lt;&lt;172:8,1:4&gt;&gt;</code> since <code>&lt;&lt;172:8,1:4,0:4&gt;&gt; ==
%% &lt;&lt;172:8,16:8&gt;&gt;</code> and <code>bit_size(&lt;&lt;172:8,1:4&gt;&gt;) == 12</code>.
%% (Most subnets are /8, /16, or /24, which should eliminate most of these kinds of conversions.)</p>
%% <p>Examples:</p>
%% <ul>
%% <li>1.0.0.0/8 == <code>&lt;&lt;1:8&gt;&gt;</code></li>
%% <li>1.2.0.0/16 == <code>&lt;&lt;1:8,2:8&gt;&gt;</code></li>
%% <li>1.2.3.0/24 == <code>&lt;&lt;1:8,2:8,3:8&gt;&gt;</code></li>
%% <li>1.2.3.4/32 (single IP) == <code>&lt;&lt;1:8,2:8,3:8,4:8&gt;&gt;</code></li>
%% <li>1.2.216.0/21 == <code>&lt;&lt;1:8,2:8,27:5&gt;&gt;</code> (since 216 == 2#11011000 and 27 == 2#11011)</li>
%% </ul>
%% @end
-type ip4_subnet() :: bitstring().

%% @doc Checks whether the specified IP matches a subnet specification in the supplied list.
%% @end
%% @spec is_ipv4_in_subnet_list(IP :: inet:ip4_address(), SubnetList :: [ip4_subnet()]) -> boolean()
-spec    is_ipv4_in_subnet_list(IP :: inet:ip4_address(), SubnetList :: [ip4_subnet()]) -> boolean().

is_ipv4_in_subnet_list(IPv4, SubnetList) ->
	NormalizedIP = normalize_ip(inet, IPv4),
	lists:any(fun(Subnet) -> ipv4_subnet_match(NormalizedIP, Subnet) end, SubnetList).

%% @doc Checks whether an IP matches a subnet specification.
%% @end
%% @spec ipv4_subnet_match(NormalizedIPv4 :: binary(), Subnet :: ip4_subnet()) -> boolean()
-spec    ipv4_subnet_match(NormalizedIPv4 :: binary(), Subnet :: ip4_subnet()) -> boolean().

ipv4_subnet_match(NormalizedIPv4, Subnet) ->
	SubnetSize = bit_size(Subnet),
	case NormalizedIPv4 of
		<<Subnet:SubnetSize/bitstring, _/bitstring>> -> true;
		_ -> false
	end.

%% @doc Converts the given IP address into a normalized form used for comparisons.
%% @end
%% @spec normalize_ip(AddrFamily :: inet:address_family(), IP :: (inet:ip_address() | binary())) -> binary()
-spec    normalize_ip(AddrFamily :: inet:address_family(), IP :: (inet:ip_address() | binary())) -> binary().

normalize_ip(inet, {A,B,C,D}) when is_integer(A), 0 =< A, A =< 255,
                                   is_integer(B), 0 =< B, B =< 255,
                                   is_integer(C), 0 =< C, C =< 255,
                                   is_integer(D), 0 =< D, D =< 255 ->
	<<A:8,B:8,C:8,D:8>>;
normalize_ip(inet6, {A,B,C,D,E,F,G,H}) when is_integer(A), 0 =< A, A =< 65535,
                                            is_integer(B), 0 =< B, B =< 65535,
                                            is_integer(C), 0 =< C, C =< 65535,
                                            is_integer(D), 0 =< D, D =< 65535,
                                            is_integer(E), 0 =< E, E =< 65535,
                                            is_integer(F), 0 =< F, F =< 65535,
                                            is_integer(G), 0 =< G, G =< 65535,
                                            is_integer(H), 0 =< H, H =< 65535 ->
	<<A:16/big,B:16/big,C:16/big,D:16/big,E:16/big,F:16/big,G:16/big,H:16/big>>;
normalize_ip(_, Bin) when is_binary(Bin) ->
	Bin.

%% @doc Convenience method for converting an odd-sized (not /8, /16, or /24) subnet mask
%% into the format used for subnet checks.
%% @end
%% @spec make_subnet(IP :: inet:ip4_address(), N :: integer()) -> bitstring()
-spec    make_subnet(IP :: inet:ip4_address(), N :: integer()) -> bitstring().

make_subnet(IP={_,_,_,_}, N) when is_integer(N), 0 =< N, N =< 32 ->
	<<Subnet:N/bitstring, _/bitstring>> = normalize_ip(inet, IP),
	Subnet.