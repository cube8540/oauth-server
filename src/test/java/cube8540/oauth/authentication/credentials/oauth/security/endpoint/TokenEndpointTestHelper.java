package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.TokenRequestKey;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenEndpointTestHelper {

    static final String RAW_TOKEN_ID = "TOKEN-ID";

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final String RAW_DIFFERENT_CLIENT_ID = "DIFFERENT-CLIENT-ID";

    static final String RAW_USERNAME = "username";
    static final String RAW_PASSWORD = "Password1234!@#$";

    static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 2, 1, 22, 52);

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));

    static final String GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE.getValue();

    static final String RAW_CODE = "CODE";

    static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    static OAuth2AccessTokenDetailsService makeEmptyAccessTokenDetailsService() {
        return mock(OAuth2AccessTokenDetailsService.class);
    }

    static OAuth2AccessTokenDetailsService makeAccessTokenDetailsService(String token, OAuth2AccessTokenDetails tokenDetails) {
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();

        when(service.readAccessToken(token)).thenReturn(tokenDetails);

        return service;
    }

    static OAuth2AccessTokenIntrospectionConverter makeIntrospectionConverter(OAuth2AccessTokenDetails accessToken, Map<String, Object> map) {
        OAuth2AccessTokenIntrospectionConverter converter = mock(OAuth2AccessTokenIntrospectionConverter.class);

        when(converter.convertAccessToken(accessToken)).thenReturn(map);

        return converter;
    }

    static OAuth2ClientDetails makeClientDetails() {
        OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);

        when(clientDetails.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(clientDetails.getScopes()).thenReturn(RAW_SCOPES);

        return clientDetails;
    }

    static OAuth2AccessTokenDetails makeAccessTokenDetails() {
        OAuth2AccessTokenDetails token = mock(OAuth2AccessTokenDetails.class);

        when(token.getTokenValue()).thenReturn(RAW_TOKEN_ID);
        when(token.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(token.getUsername()).thenReturn(RAW_USERNAME);
        when(token.getExpiration()).thenReturn(EXPIRATION);
        when(token.getScopes()).thenReturn(RAW_SCOPES);
        when(token.getExpired()).thenReturn(false);

        return token;
    }

    static Map<String, Object> makeAccessTokenMap() {
        return new HashMap<>();
    }

    static ClientCredentialsToken makeClientCredentialsToken(Object clientDetails) {
        ClientCredentialsToken principal = mock(ClientCredentialsToken.class);

        when(principal.getPrincipal()).thenReturn(clientDetails);
        return principal;
    }

    static Principal makeNotClientCredentialsTokenPrincipal() {
        return mock(Principal.class);
    }

    static Map<String, String> makeRequestMap() {
        Map<String, String> map = new HashMap<>();

        map.put(TokenRequestKey.GRANT_TYPE, GRANT_TYPE);
        map.put(TokenRequestKey.USERNAME, RAW_USERNAME);
        map.put(TokenRequestKey.PASSWORD, RAW_PASSWORD);
        map.put(TokenRequestKey.CLIENT_ID, RAW_CLIENT_ID);
        map.put(TokenRequestKey.CODE, RAW_CODE);
        map.put(TokenRequestKey.REDIRECT_URI, REDIRECT_URI.toString());
        map.put(TokenRequestKey.SCOPE, String.join(" ", RAW_SCOPES));

        return map;
    }

    static Map<String, String> makeRequestMapGrantTypeNull() {
        Map<String, String> map = makeRequestMap();

        map.put(TokenRequestKey.GRANT_TYPE, null);

        return map;
    }

    static Map<String, String> makeRequestMapGrantTypeImplicit() {
        Map<String, String> map = makeRequestMap();

        map.put(TokenRequestKey.GRANT_TYPE, AuthorizationGrantType.IMPLICIT.getValue());

        return map;
    }

    static OAuth2AccessTokenGranter makeTokenGrantService(OAuth2AccessTokenDetails token) {
        OAuth2AccessTokenGranter service = mock(OAuth2AccessTokenGranter.class);

        when(service.grant(any(), any())).thenReturn(token);
        return service;
    }

    static OAuth2TokenRevoker makeRevokeService(OAuth2AccessTokenDetails accessToken) {
        OAuth2TokenRevoker service = mock(OAuth2TokenRevoker.class);

        when(service.revoke(any())).thenReturn(accessToken);
        return service;
    }
}