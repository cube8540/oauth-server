package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2AuthorizationCodeTestHelper {
    static final String RAW_CODE = "CODE";
    static final AuthorizationCode CODE = new AuthorizationCode(RAW_CODE);

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    static final String RAW_USERNAME = "email@email.com";
    static final UserEmail USERNAME = new UserEmail(RAW_USERNAME);

    static final String STATE = "STATE";

    static final String RAW_REDIRECT_URI = "http://localhost";
    static final URI REDIRECT_URI = URI.create(RAW_REDIRECT_URI);

    static final LocalDateTime NOW = LocalDateTime.of(2020, 2, 8, 23, 22);
    static final LocalDateTime EXPIRATION_DATETIME = NOW.plusMinutes(5);

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<OAuth2ScopeId> SCOPES = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    static AuthorizationCodeGenerator configDefaultCodeGenerator() {
        AuthorizationCodeGenerator generator = mock(AuthorizationCodeGenerator.class);
        when(generator.generate()).thenReturn(CODE);
        return generator;
    }

    static MockAuthorizationRequest mockAuthorizationRequest() {
        return new MockAuthorizationRequest();
    }

    static class MockAuthorizationRequest {
        private AuthorizationRequest request;

        private MockAuthorizationRequest() {
            this.request = mock(AuthorizationRequest.class);
        }

        MockAuthorizationRequest configDefaultSetup() {
            configDefaultClientId();
            configDefaultUsername();
            configDefaultState();
            configDefaultRedirectUri();
            configDefaultRequestScope();
            return this;
        }

        MockAuthorizationRequest configDefaultClientId() {
            when(request.getClientId()).thenReturn(RAW_CLIENT_ID);
            return this;
        }

        MockAuthorizationRequest configMismatchesClientId() {
            when(request.getClientId()).thenReturn("NOT MATCHED CLIENT ID");
            return this;
        }

        MockAuthorizationRequest configDefaultUsername() {
            when(request.getUsername()).thenReturn(RAW_USERNAME);
            return this;
        }

        MockAuthorizationRequest configDefaultState() {
            when(request.getState()).thenReturn(STATE);
            return this;
        }

        MockAuthorizationRequest configMismatchesState() {
            when(request.getState()).thenReturn("NOT MATCHED STATE");
            return this;
        }

        MockAuthorizationRequest configDefaultRedirectUri() {
            when(request.getRedirectUri()).thenReturn(REDIRECT_URI);
            return this;
        }

        MockAuthorizationRequest configRedirectUriNull() {
            when(request.getRedirectUri()).thenReturn(null);
            return this;
        }

        MockAuthorizationRequest configMismatchesRedirectUri() {
            when(request.getRedirectUri()).thenReturn(URI.create("http://localhost:8081"));
            return this;
        }

        MockAuthorizationRequest configDefaultRequestScope() {
            when(request.getRequestScopes()).thenReturn(RAW_SCOPES);
            return this;
        }

        AuthorizationRequest build() {
            return request;
        }
    }
}
