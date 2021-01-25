package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.AccessTokenIntrospectionKey;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.EXPIRATION;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeAccessTokenDetails;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

@DisplayName("기본 엑세스 토큰")
class DefaultOAuth2AccessTokenIntrospectionConverterTest {

    @Test
    @DisplayName("액세스 토큰의 유저 명이 null 일때")
    void whenAccessTokenUsernameIsNull() {
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        DefaultOAuth2AccessTokenIntrospectionConverter converter = new DefaultOAuth2AccessTokenIntrospectionConverter();

        when(accessToken.getUsername()).thenReturn(null);

        Map<String, Object> result = converter.convertAccessToken(accessToken);
        assertEquals(RAW_CLIENT_ID, result.get(AccessTokenIntrospectionKey.CLIENT_ID));
        assertEquals(EXPIRATION.atZone(DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond(), result.get(AccessTokenIntrospectionKey.EXPIRATION));
        assertEquals(String.join(" ", RAW_SCOPES), result.get(AccessTokenIntrospectionKey.SCOPE));
        assertNull(result.get(AccessTokenIntrospectionKey.USERNAME));
    }

    @Test
    @DisplayName("액세스 토큰이 만료 되었을 때")
    void whenAccessTokenExpiration() {
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        DefaultOAuth2AccessTokenIntrospectionConverter converter = new DefaultOAuth2AccessTokenIntrospectionConverter();

        when(accessToken.getExpired()).thenReturn(true);

        Map<String, Object> result = converter.convertAccessToken(accessToken);
        assertEquals(RAW_CLIENT_ID, result.get(AccessTokenIntrospectionKey.CLIENT_ID));
        assertEquals(EXPIRATION.atZone(DEFAULT_TIME_ZONE.toZoneId()).toEpochSecond(), result.get(AccessTokenIntrospectionKey.EXPIRATION));
        assertEquals(String.join(" ", RAW_SCOPES), result.get(AccessTokenIntrospectionKey.SCOPE));
        assertEquals(RAW_USERNAME, result.get(AccessTokenIntrospectionKey.USERNAME));
        assertFalse(Boolean.parseBoolean(result.get(AccessTokenIntrospectionKey.ACTIVE).toString()));
    }
}