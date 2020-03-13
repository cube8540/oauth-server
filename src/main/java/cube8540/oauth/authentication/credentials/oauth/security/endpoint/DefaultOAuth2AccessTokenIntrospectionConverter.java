package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;

import java.util.HashMap;
import java.util.Map;

public class DefaultOAuth2AccessTokenIntrospectionConverter implements OAuth2AccessTokenIntrospectionConverter {
    @Override
    public Map<String, Object> convertAccessToken(OAuth2AccessTokenDetails accessToken) {
        Map<String, Object> result = new HashMap<>();

        result.put(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE, true);
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.CLIENT_ID, accessToken.getClientId());
        if (accessToken.getUsername() != null) {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, accessToken.getUsername());
        } else {
            result.put(OAuth2Utils.AccessTokenIntrospectionKey.USERNAME, null);
        }

        long expiration = accessToken.getExpiration().atZone(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond();
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.EXPIRATION, expiration);

        String scope = String.join(" ", accessToken.getScopes());
        result.put(OAuth2Utils.AccessTokenIntrospectionKey.SCOPE, scope);
        return result;
    }
}
