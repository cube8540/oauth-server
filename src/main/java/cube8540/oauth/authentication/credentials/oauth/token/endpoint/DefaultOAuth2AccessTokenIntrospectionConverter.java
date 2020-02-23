package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class DefaultOAuth2AccessTokenIntrospectionConverter implements OAuth2AccessTokenIntrospectionConverter {
    @Override
    public Map<String, Object> convertAccessToken(OAuth2AccessTokenDetails accessToken) {
        Map<String, Object> result = new HashMap<>();

        result.put(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE, true);
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.CLIENT_ID, accessToken.getClientId().getValue());
        if (accessToken.getUsername() != null) {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, accessToken.getUsername());
        } else {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, null);
        }

        long expiration = accessToken.getExpiration().atZone(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond();
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.EXPIRATION, expiration);

        String scope = accessToken.getScopes().stream().map(OAuth2ScopeId::getValue).collect(Collectors.joining(" "));
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.SCOPE, scope);
        return result;
    }
}
