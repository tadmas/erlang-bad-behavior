%--------------------------------------------------------------------------
%% @author David K. Jones [http://www.tadmas.com/]
%% @doc Converts error codes into a format suitable for displaying in an error page.
%% @end
%--------------------------------------------------------------------------
-module(badbehavior_response).

-export([support_key/1, http_status/1, log_message/1, display_message/1]).

%% @doc Returns the support key for a given error code.
%% @end
%% spec support_key(Error :: atom()) -> string()
-spec   support_key(Error :: atom()) -> string().
support_key(Error) ->
	{SupportKey,_,_,_} = get_definition(Error),
	SupportKey.

%% @doc Returns which HTTP status code should be used for a given error code.
%% @end
%% spec http_status(Error :: atom()) -> integer()
-spec   http_status(Error :: atom()) -> integer().
http_status(Error) ->
	{_,StatusCode,_,_} = get_definition(Error),
	StatusCode.

%% @doc Returns the internal log message for a given error code.
%% @end
%% spec log_message(Error :: atom()) -> string()
-spec   log_message(Error :: atom()) -> string().
log_message(Error) ->
	{_,_,LogMessage,_} = get_definition(Error),
	LogMessage.

%% @doc Returns the error message to display to the user for a given error code.
%% @end
%% spec display_message(Error :: atom()) -> string()
-spec   display_message(Error :: atom()) -> string().
display_message(Error) ->
	{_,_,_,Message} = get_definition(Error),
	Message.

%% @type response_definition() =  {SupportKey :: string(), StatusCode :: integer(),
%%                                 LogMessage :: string(), Message :: string()}.
-type    response_definition() :: {SupportKey :: string(), StatusCode :: integer(),
                                   LogMessage :: string(), Message :: string()}.

%% @doc Returns information about a given error code.
%% @end
%% @spec get_definition(Error :: atom()) -> response_definition()
-spec    get_definition(Error :: atom()) -> response_definition().

get_definition(blacklist_ip) ->
	{"136673cd", 403, "IP address found on external blacklist",
	"Your Internet Protocol address is listed on a blacklist of addresses involved in malicious or illegal activity. See the listing below for more details on specific blacklists and removal procedures."};
get_definition(noaccept) ->
	{"17566707", 403, "Required header 'Accept' missing",
	"An invalid request was received from your browser. This may be caused by a malfunctioning proxy server or browser privacy software."};
get_definition(blacklist_ua) ->
	{"17f4e8c8", 403, "User-Agent was found on blacklist",
	"You do not have permission to access this server."};
% TODO: does not appear to be referenced
%get_definition(notavantgo) ->
%	{"21f11d3f", 403, "User-Agent claimed to be AvantGo, claim appears false",
%	"An invalid request was received. You claimed to be a mobile Web device, but you do not actually appear to be a mobile Web device."};
get_definition(blacklist_httpbl) ->
	{"2b021b1f", 403, "IP address found on http:BL blacklist",
	"You do not have permission to access this server. Before trying again, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(connectionteforie) ->
	{"2b90f772", 403, "Connection: TE present, not supported by MSIE",
	"You do not have permission to access this server. If you are using the Opera browser, then Opera must appear in your user agent."};
get_definition(badlang) ->
	{"35ea7ffa", 403, "Invalid language specified",
	"You do not have permission to access this server. Check your browser's language and locale settings."};
% TODO: only reference is commented out
%get_definition(quickpost) ->
%	{"408d7e72", 403, "POST comes too quickly after GET",
%	"You do not have permission to access this server. Before trying again, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(badpragma) ->
	{"41feed15", 400, "Header 'Pragma' without 'Cache-Control' prohibited for HTTP/1.1 requests",
	"An invalid request was received. This may be caused by a malfunctioning proxy server. Bypass the proxy server and connect directly, or contact your proxy server administrator."};
get_definition(badreferer) ->
	{"45b35e30", 400, "Header 'Referer' is corrupt",
	"An invalid request was received from your browser. This may be caused by a malfunctioning proxy server or browser privacy software."};
% TODO: does not appear to be referenced
%get_definition(hasxaaaaaaaaaa) ->
%	{"57796684", 403, "Prohibited header 'X-Aaaaaaaaaa' or 'X-Aaaaaaaaaaaa' present",
%	"You do not have permission to access this server. Before trying again, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(noconnectionte) ->
	{"582ec5e4", 400, "Header 'TE' present but TE not specified in 'Connection' header",
	"An invalid request was received. If you are using a proxy server, bypass the proxy server or contact your proxy server administrator. This may also be caused by a bug in the Opera web browser."};
get_definition(blankreferer) ->
	{"69920ee5", 400, "Header 'Referer' present but blank",
	"An invalid request was received from your browser. This may be caused by a malfunctioning proxy server or browser privacy software."};
get_definition(badcookie) ->
	{"6c502ff1", 403, "Bot not fully compliant with RFC 2965",
	"You do not have permission to access this server."};
get_definition(notcloudflare) ->
	{"70e45496", 403, "User agent claimed to be CloudFlare, claim appears false",
	"You do not have permission to access this server."};
get_definition(notyahoo) ->
	{"71436a15", 403, "User-Agent claimed to be Yahoo, claim appears to be false",
	"An invalid request was received. You claimed to be a major search engine, but you do not appear to actually be a major search engine."};
% TODO: only reference is commented out
%get_definition(changingua) ->
%	{"799165c2", 403, "Rotating user-agents detected",
%	"You do not have permission to access this server."};
% TODO: does not appear to be referenced
%get_definition(noacceptencoding) ->
%	{"7a06532b", 400, "Required header 'Accept-Encoding' missing",
%	"An invalid request was received from your browser. This may be caused by a malfunctioning proxy server or browser privacy software."};
get_definition(hasrange) ->
	{"7ad04a8a", 400, "Prohibited header 'Range' present",
	"The automated program you are using is not permitted to access this server. Please use a different program or a standard Web browser."};
get_definition(hasrangeinpost) ->
	{"7d12528e", 403, "Prohibited header 'Range' or 'Content-Range' in POST request",
	"You do not have permission to access this server."};
get_definition(bannedproxy) ->
	{"939a6fbb", 403, "Banned proxy server in use",
	"The proxy server you are using is not permitted to access this server. Please bypass the proxy server, or contact your proxy server administrator."};
get_definition(hasvia) ->
	{"9c9e4979", 403, "Prohibited header 'via' present",
	"The proxy server you are using is not permitted to access this server. Please bypass the proxy server, or contact your proxy server administrator."};
get_definition(hasexpect) ->
	{"a0105122", 417, "Header 'Expect' prohibited; resend without Expect",
	"Expectation failed. Please retry your request."};
get_definition(iewinver) ->
	{"a1084bad", 403, "User-Agent claimed to be MSIE, with invalid Windows version",
	"You do not have permission to access this server."};
get_definition(badconnection) ->
	{"a52f0448", 400, "Header 'Connection' contains invalid values",
	"An invalid request was received.  This may be caused by a malfunctioning proxy server or browser privacy software. If you are using a proxy server, bypass the proxy server or contact your proxy server administrator."};
get_definition(badkeepalive) ->
	{"b0924802", 400, "Incorrect form of HTTP/1.0 Keep-Alive",
	"An invalid request was received. This may be caused by malicious software on your computer."};
get_definition(slowpost) ->
	{"b40c8ddc", 403, "POST more than two days after GET",
	"You do not have permission to access this server. Before trying again, close your browser, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(hasproxyconnection) ->
	{"b7830251", 400, "Prohibited header 'Proxy-Connection' present",
	"Your proxy server sent an invalid request. Please contact the proxy server administrator to have this problem fixed."};
get_definition(hasxaaaaaaaaaa) ->
	{"b9cc1d86", 403, "Prohibited header \'X-Aaaaaaaaaa\' or \'X-Aaaaaaaaaaaa\' present",
	"The proxy server you are using is not permitted to access this server. Please bypass the proxy server, or contact your proxy server administrator."};
get_definition(changingproxy) ->
	{"c1fa729b", 403, "Use of rotating proxy servers detected",
	"You do not have permission to access this server. Before trying again, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(offsitereferer) ->
	{"cd361abb", 403, "Referer did not point to a form on this site",
	"You do not have permission to access this server. Data may not be posted from offsite forms."};
get_definition(proxytrackback) ->
	{"d60b87c7", 403, "Trackback received via proxy server",
	"You do not have permission to access this server. Before trying again, please remove any viruses or spyware from your computer."};
get_definition(injectionattack) ->
	{"dfd9b1ad", 403, "Request contained a malicious JavaScript or SQL injection attack",
	"You do not have permission to access this server."};
get_definition(badtrackback) ->
	{"e3990b47", 403, "Obviously fake trackback received",
	"You do not have permission to access this server. Before trying again, please remove any viruses or spyware from your computer."};
get_definition(notmsnbot) ->
	{"e4de0453", 403, "User-Agent claimed to be msnbot, claim appears to be false",
	"An invalid request was received. You claimed to be a major search engine, but you do not appear to actually be a major search engine."};
% TODO: This does not appear to be set anywhere.
%get_definition(???) ->
%	{"e87553e1", 403, "I know you and I don't like you, dirty spammer.",
%	"You do not have permission to access this server."};
get_definition(browsertrackback) ->
	{"f0dcb3fd", 403, "Web browser attempted to send a trackback",
	"You do not have permission to access this server. Before trying again, run anti-virus and anti-spyware software and remove any viruses and spyware from your computer."};
get_definition(notgooglebot) ->
	{"f1182195", 403, "User-Agent claimed to be Googlebot, claim appears to be false.",
	"An invalid request was received. You claimed to be a major search engine, but you do not appear to actually be a major search engine."};
get_definition(noua) ->
	{"f9f2b8b9", 403, "A User-Agent is required but none was provided.",
	"You do not have permission to access this server. This may be caused by a malfunctioning proxy server or browser privacy software."}.
