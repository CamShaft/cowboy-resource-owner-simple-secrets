-module(cowboy_resource_owner_simple_secrets).

-export([handle/2]).

handle(Token, Env) ->
  case key(ss_token_secret, Env) of
    undefined ->
      {error, secret_not_found};
    Secret ->
      case decrypt(Token, Secret) of
        undefined ->
          {error, invalid_token};
        Body ->
          Enum = key(ss_scopes_enum, Env, []),
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
  case simple_secrets:unpack(Token, Secret) of
    {error, _} = Error ->
      Error;
    Body ->
      Body
  end.

transform(Body, Enum) ->
  % {ClientID, OwnerID, Scopes, Expiration, Other}
  {
    key(<<"c">>, Body),
    key(<<"u">>, Body),
    bitfield:unpack(key(<<"s">>, Body, <<>>), Enum),
    key(<<"e">>, Body),
    undefined
  }.

verify({_ClientID, _OwnerID, _Scopes, _Expiration, _Other}) ->
  % TODO check expiration
  true.

key(Key, List) ->
  key(Key, List, undefined).
key(Key, List, Default) ->
  {_, Value} = lists:keyfind(Key, 1, List),
  case Value of
    undefined ->
      Default;
    Value ->
      Value
  end.
