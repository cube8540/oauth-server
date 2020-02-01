package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultOAuth2AccessTokenIntrospectionConverter implements OAuth2AccessTokenIntrospectionConverter {
    @Override
    public Map<String, Object> convertAccessToken(OAuth2AuthorizedAccessToken accessToken) {
        Map<String, Object> result = new HashMap<>();

        result.put(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE, true);
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.CLIENT_ID, accessToken.getClient().getValue());
        if (accessToken.getEmail() != null) {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, accessToken.getEmail().getValue());
        } else {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, null);
        }

        long expiration = accessToken.getExpiration().atZone(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond();
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.EXPIRATION, expiration);

        String scope = accessToken.getScope().stream().map(OAuth2ScopeId::getValue).collect(Collectors.joining(" "));
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.SCOPE, scope);
        return result;
    }
}
