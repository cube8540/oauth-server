package cube8540.oauth.authentication.credentials.oauth;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.application.DefaultOAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientDefaultSecret;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 클라이언트 디테일즈 서비스 테스트")
class DefaultOAuth2ClientDetailsServiceTest {

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_SECRET = "SECRET";
    private static final OAuth2ClientDefaultSecret SECRET = new OAuth2ClientDefaultSecret(RAW_SECRET);
    private static final String CLIENT_NAME = "CLIENT-NAME";

    private static final Set<URI> REGISTERED_REDIRECT_URI = new HashSet<>(Arrays.asList(
            URI.create("http://localhost:80"), URI.create("http://localhost:81"), URI.create("http://localhost:82")));

    private static final Set<AuthorizationGrantType> AUTHORIZED_GRANT_TYPE = new HashSet<>(Arrays.asList(
            AuthorizationGrantType.AUTHORIZATION_CODE,
            AuthorizationGrantType.CLIENT_CREDENTIALS,
            AuthorizationGrantType.IMPLICIT,
            AuthorizationGrantType.PASSWORD,
            AuthorizationGrantType.REFRESH_TOKEN));

    private static final Set<OAuth2ScopeId> SCOPE = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3")));

    private static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10);

    private static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofHours(2);

    private OAuth2Client client;

    private OAuth2ClientRepository repository;
    private OAuth2ClientDetailsService service;

    @BeforeEach
    void setup() {
        this.client = mock(OAuth2Client.class);
        this.repository = mock(OAuth2ClientRepository.class);
        this.service = new DefaultOAuth2ClientDetailsService(repository);
    }

    @Nested
    @DisplayName("클라이언트 검색")
    class LoadClientDetails {

        @Nested
        @DisplayName("클라이언트를 찾을 수 없을시")
        class WhenNotFoundClient {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(any())).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("OAuth2ClientNotFoundException이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(OAuth2ClientNotFoundException.class, () -> service.loadClientDetailsByClientId(RAW_CLIENT_ID));
            }
        }

        @Nested
        @DisplayName("클라이언트를 찾았을시")
        class WhenFoundClient {

            @BeforeEach
            void setup() {
                when(client.getClientId()).thenReturn(CLIENT_ID);
                when(client.getSecret()).thenReturn(SECRET);
                when(client.getClientName()).thenReturn(CLIENT_NAME);
                when(client.getRedirectURI()).thenReturn(REGISTERED_REDIRECT_URI);
                when(client.getGrantType()).thenReturn(AUTHORIZED_GRANT_TYPE);
                when(client.getScope()).thenReturn(SCOPE);
                when(client.getAccessTokenValidity()).thenReturn(ACCESS_TOKEN_VALIDITY);
                when(client.getRefreshTokenValidity()).thenReturn(REFRESH_TOKEN_VALIDITY);
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
            }

            @Test
            @DisplayName("검색된 클라이언트의 아이디를 반환해야 한다.")
            void shouldReturnsClientId() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertEquals(RAW_CLIENT_ID, result.clientId());
            }

            @Test
            @DisplayName("검색된 클라이언트의 패스워드를 반환해야 한다.")
            void shouldReturnsSecret() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertEquals(RAW_SECRET, result.clientSecret());
            }

            @Test
            @DisplayName("검색된 클라이언트명을 반환해야 한다.")
            void shouldReturnClientName() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertEquals(CLIENT_NAME, result.clientName());
            }

            @Test
            @DisplayName("검색된 클라이언트의 리다이렉트 URI를 반환해야 한다.")
            void shouldReturnsClientRedirectURI() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertTrue(result.registeredRedirectURI().contains(URI.create("http://localhost:80")));
                assertTrue(result.registeredRedirectURI().contains(URI.create("http://localhost:81")));
                assertTrue(result.registeredRedirectURI().contains(URI.create("http://localhost:82")));
            }

            @Test
            @DisplayName("검색된 클라이언트의 인증 방식을 반환해야 한다.")
            void shouldReturnsClientGrantType() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertTrue(result.authorizedGrantType().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
                assertTrue(result.authorizedGrantType().contains(AuthorizationGrantType.CLIENT_CREDENTIALS));
                assertTrue(result.authorizedGrantType().contains(AuthorizationGrantType.IMPLICIT));
                assertTrue(result.authorizedGrantType().contains(AuthorizationGrantType.REFRESH_TOKEN));
                assertTrue(result.authorizedGrantType().contains(AuthorizationGrantType.PASSWORD));
            }

            @Test
            @DisplayName("검색된 클라이언트의 스코프를 반환해야 한다.")
            void shouldReturnsClientScope() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                assertTrue(result.scope().contains("SCOPE-1"));
                assertTrue(result.scope().contains("SCOPE-2"));
                assertTrue(result.scope().contains("SCOPE-3"));
            }

            @Test
            @DisplayName("검색된 클라이언트의 액세스 토큰의 유효시간을 초로 환산하여 반환해야 한다.")
            void shouldReturnsClientAccessTokenValiditySeconds() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                int seconds = Double.valueOf(ACCESS_TOKEN_VALIDITY.toSeconds()).intValue();
                assertEquals(seconds, result.accessTokenValiditySeconds());
            }

            @Test
            @DisplayName("검색된 클라이언트의 리플래시 토큰의 유효시간을 초로 환산하여 반환해야 한다.")
            void shouldReturnsClientRefreshTokenValiditySeconds() {
                OAuth2ClientDetails result = service.loadClientDetailsByClientId(RAW_CLIENT_ID);

                int seconds = Double.valueOf(REFRESH_TOKEN_VALIDITY.toSeconds()).intValue();
                assertEquals(seconds, result.refreshTokenValiditySeconds());
            }
        }
    }

}