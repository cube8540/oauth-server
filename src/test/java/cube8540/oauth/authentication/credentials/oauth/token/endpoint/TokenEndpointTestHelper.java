package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenGrantService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenReadService;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenRevokeService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenEndpointTestHelper {

    static final String RAW_TOKEN_ID = "TOKEN-ID";

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);
    static final String RAW_DIFFERENT_CLIENT_ID = "DIFFERENT-CLIENT-ID";
    static final OAuth2ClientId DIFFERENT_CLIENT_ID = new OAuth2ClientId(RAW_DIFFERENT_CLIENT_ID);

    static final String RAW_USERNAME = "email@email.com";
    static final String RAW_PASSWORD = "Password1234!@#$";

    static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 2, 1, 22, 52);

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<OAuth2ScopeId> SCOPES = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    static final String GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE.getValue();

    static final String RAW_CODE = "CODE";

    static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    static MockAccessToken mockAccessToken() {
        return new MockAccessToken();
    }

    static MockAccessTokenReadService mockAccessTokenReadService() {
        return new MockAccessTokenReadService();
    }

    static MockClientDetails mockClientDetails() {
        return new MockClientDetails();
    }

    static MockIntrospectionConverter mockIntrospectionConverter() {
        return new MockIntrospectionConverter();
    }

    static Principal mockPrincipal(OAuth2ClientDetails clientDetails) {
        ClientCredentialsToken principal = mock(ClientCredentialsToken.class);

        when(principal.getPrincipal()).thenReturn(clientDetails);
        return principal;
    }

    static Principal mockDetailsNotOAuth2ClientDetailsPrincipal() {
        ClientCredentialsToken principal = mock(ClientCredentialsToken.class);

        when(principal.getPrincipal()).thenReturn(new Object());
        return principal;
    }

    static Principal mockNotClientCredentialsTokenPrincipal() {
        return mock(Principal.class);
    }

    static MockTokenRequestMap mockTokenRequestMap() {
        return new MockTokenRequestMap();
    }

    static OAuth2AccessTokenGrantService mockTokenGrantService(OAuth2AccessTokenDetails token) {
        OAuth2AccessTokenGrantService service = mock(OAuth2AccessTokenGrantService.class);

        when(service.grant(any(), any())).thenReturn(token);
        return service;
    }

    static OAuth2TokenRevokeService mockRevokeService(OAuth2AccessTokenDetails accessToken) {
        OAuth2TokenRevokeService service = mock(OAuth2TokenRevokeService.class);

        when(service.revoke(any())).thenReturn(accessToken);
        return service;
    }

    static class MockAccessToken {
        private OAuth2AccessTokenDetails token;

        private MockAccessToken() {
            this.token = mock(OAuth2AccessTokenDetails.class);
        }

        MockAccessToken configDefault() {
            when(token.getTokenValue()).thenReturn(RAW_TOKEN_ID);
            when(token.getClientId()).thenReturn(CLIENT_ID);
            when(token.getUsername()).thenReturn(RAW_USERNAME);
            when(token.getExpiration()).thenReturn(EXPIRATION);
            when(token.getScopes()).thenReturn(SCOPES);
            return this;
        }

        MockAccessToken configClientAuthentication() {
            when(token.getUsername()).thenReturn(null);
            return this;
        }

        MockAccessToken configDifferentClientId() {
            when(token.getClientId()).thenReturn(DIFFERENT_CLIENT_ID);
            return this;
        }

        OAuth2AccessTokenDetails build() {
            return token;
        }
    }

    static class MockAccessTokenReadService {
        private OAuth2AccessTokenReadService service;

        private MockAccessTokenReadService() {
            this.service = mock(OAuth2AccessTokenReadService.class);
        }

        MockAccessTokenReadService registerToken(OAuth2AccessTokenDetails token) {
            when(service.readAccessToken(RAW_TOKEN_ID)).thenReturn(token);
            return this;
        }

        OAuth2AccessTokenReadService build() {
            return service;
        }
    }

    static class MockClientDetails {
        private OAuth2ClientDetails client;

        private MockClientDetails() {
            this.client = mock(OAuth2ClientDetails.class);
        }

        MockClientDetails configDefault() {
            when(client.getClientId()).thenReturn(RAW_CLIENT_ID);
            return this;
        }

        OAuth2ClientDetails build() {
            return client;
        }
    }

    static class MockIntrospectionConverter {
        private OAuth2AccessTokenIntrospectionConverter converter;

        private MockIntrospectionConverter() {
            this.converter = mock(OAuth2AccessTokenIntrospectionConverter.class);
        }

        MockIntrospectionConverter configConverting(OAuth2AccessTokenDetails token, Map<String, Object> map) {
            when(converter.convertAccessToken(token)).thenReturn(map);
            return this;
        }

        OAuth2AccessTokenIntrospectionConverter build() {
            return converter;
        }
    }

    static class MockTokenRequestMap {
        private Map<String, String> requestMap;

        private MockTokenRequestMap() {
            this.requestMap = new HashMap<>();
        }

        MockTokenRequestMap configDefault() {
            this.requestMap.put(OAuth2Utils.TokenRequestKey.GRANT_TYPE, GRANT_TYPE);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.USERNAME, RAW_USERNAME);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.PASSWORD, RAW_PASSWORD);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.CLIENT_ID, RAW_CLIENT_ID);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.CODE, RAW_CODE);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.REDIRECT_URI, REDIRECT_URI.toString());
            this.requestMap.put(OAuth2Utils.TokenRequestKey.SCOPE, String.join(" ", RAW_SCOPES));
            return this;
        }

        MockTokenRequestMap configGrantType(String grantType) {
            this.requestMap.put(OAuth2Utils.TokenRequestKey.GRANT_TYPE, grantType);
            return this;
        }

        Map<String, String> build() {
            return requestMap;
        }
    }
}