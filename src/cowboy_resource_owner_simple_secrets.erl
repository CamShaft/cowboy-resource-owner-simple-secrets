-module(cowboy_resource_owner_simple_secrets).

-export([handle/2]).
-export([init/2]).

handle(Token, Env) ->
  Fun = init(fast_key:get(ss_token_secret, Env), fast_key:get(ss_scopes_enum, Env)),
  Fun(Token, Env).

init(Secret, Enum) when is_binary(Secret), is_list(Enum) ->
  Signer = simple_secrets:init(Secret),
  init(Signer, Enum);
init(Signer, Enum) when is_list(Enum) ->
  fun (Token, _Env) ->
    case decrypt(Token, Signer) of
      undefined ->
        {error, invalid_token};
      Body ->
        Transformed = transform(Body, Enum),
        case verify(Transformed) of
          true ->
            Transformed;
          _ ->
            {error, expired}
        end
    end
  end.

decrypt(Token, Signer) ->
  try simple_secrets:unpack(Token, Signer) of
    {error, _} = Error ->
      Error;
    {Body} ->
      Body
  catch
    _:_ ->
      undefined
  end.

transform(Body, Enum) ->
  % {ClientID, OwnerID, Scopes, Expiration, Other}
  {
    fast_key:get(<<"c">>, Body),
    fast_key:get(<<"u">>, Body),
    bitfield:unpack(fast_key:get(<<"s">>, Body, <<>>), Enum),
    fast_key:get(<<"e">>, Body),
    undefined
  }.

verify({_ClientID, _OwnerID, _Scopes, _Expiration, _Other}) ->
  % TODO check expiration
  true.
