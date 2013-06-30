-module(cowboy_resource_owner_simple_secrets).

-export([handle/2]).

handle(Token, Env) ->
  case fast_key:get(ss_token_secret, Env) of
    undefined ->
      {error, secret_not_found};
    Secret ->
      case decrypt(Token, Secret) of
        undefined ->
          {error, invalid_token};
        Body ->
          Enum = fast_key:get(ss_scopes_enum, Env, []),
          Transformed = transform(Body, Enum),
          case verify(Transformed) of
            true ->
              Transformed;
            _ ->
              {error, expired}
          end
      end
  end.

decrypt(Token, Secret) when is_binary(Secret) ->
  decrypt(Token, simple_secrets:init(Secret));
decrypt(Token, Secret) ->
  try simple_secrets:unpack(Token, Secret) of
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
