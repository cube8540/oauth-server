package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 클라이언트 디테일즈 서비스 테스트")
class DefaultOAuth2ClientDetailsServiceTest {

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_SECRET = "SECRET";
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

    private static final String RAW_OWNER = "owner@email.com";
    private static final UserEmail OWNER = new UserEmail(RAW_OWNER);

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
    }

}