package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 토큰 부여 추상 클래스 테스트")
class AbstractOAuth2TokenGranterTest {

    private static final String RAW_TOKEN_ID = "TOKEN_ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_CLIENT = "CLIENT";
    private static final OAuth2ClientId CLIENT = new OAuth2ClientId(RAW_CLIENT);

    private static final Set<String> RAW_SCOPE = new HashSet<>(Arrays.asList("SCOPE_1", "SCOPE_2", "SCOPE_3"));
    private static final Set<OAuth2ScopeId> SCOPE = RAW_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    private static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 1, 24, 21, 24, 0);
    private static final long EXPIRATION_IN = 600000;

    private static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    private static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    private static final boolean IS_EXPIRED = true;

    private OAuth2AccessTokenRepository repository;
    private OAuth2TokenEnhancer enhancer;

    private AbstractOAuth2TokenGranter granter;

    @BeforeEach
    void setup() {
        this.granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);
        this.repository = mock(OAuth2AccessTokenRepository.class);
        this.enhancer = mock(OAuth2TokenEnhancer.class);

        granter.setTokenRepository(repository);
        granter.setTokenEnhancer(enhancer);
    }

    @Nested
    @DisplayName("엑세스 토큰 부여 테스트")
    class GrantAccessToken {
        private OAuth2AuthorizedAccessToken accessToken;
        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        @BeforeEach
        void setup() {
            this.accessToken = mock(OAuth2AuthorizedAccessToken.class);
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);

            when(clientDetails.getClientId()).thenReturn(RAW_CLIENT);
            when(accessToken.getTokenId()).thenReturn(TOKEN_ID);
            when(accessToken.getEmail()).thenReturn(EMAIL);
            when(accessToken.getClient()).thenReturn(CLIENT);
            when(accessToken.getScope()).thenReturn(SCOPE);
            when(accessToken.getExpiration()).thenReturn(EXPIRATION);
            when(accessToken.getTokenGrantType()).thenReturn(GRANT_TYPE);
            when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
            when(accessToken.expiresIn()).thenReturn(EXPIRATION_IN);
            when(accessToken.isExpired()).thenReturn(IS_EXPIRED);
            when(granter.createAccessToken(clientDetails, tokenRequest)).thenReturn(accessToken);
        }

        @Test
        @DisplayName("생성된 엑세스 토큰을 저장해야 한다.")
        void shouldSaveAccessTokenCreatedByFactory() {
            granter.grant(clientDetails, tokenRequest);

            verify(repository, times(1)).save(accessToken);
        }

        @Nested
        @DisplayName("엑세스 토큰의 소유자가 요청한 클라이언트로 이미 인증을 받은 상태일시")
        class WhenAccessTokenUserAlreadyAuthenticationByRequestingClient {

            private OAuth2AuthorizedAccessToken existsToken;

            @BeforeEach
            void setup() {
                this.existsToken = mock(OAuth2AuthorizedAccessToken.class);

                when(repository.findByClientAndEmail(CLIENT, EMAIL)).thenReturn(Optional.of(existsToken));
            }

            @Test
            @DisplayName("저장소에서 반환된 엑세스 토큰을 삭제해야 한다.")
            void shouldRemoveReturnsAccessToken() {
                granter.grant(clientDetails, tokenRequest);

                verify(repository, times(1)).delete(existsToken);
            }

            @AfterEach
            void after() {
                when(repository.findByClientAndEmail(any(), any())).thenReturn(Optional.empty());
            }
        }

        @Test
        @DisplayName("토큰의 타입은 Bearer이어야 한다.")
        void shouldTokenTypeMustBearer() {
            OAuth2AccessTokenDetails tokenDetails = granter.grant(clientDetails, tokenRequest);

            assertEquals("Bearer", tokenDetails.tokenType());
        }

        @Test
        @DisplayName("설정된 Enhancer를 사용해야 한다.")
        void shouldUsingEnhancer() {
            granter.grant(clientDetails, tokenRequest);

            verify(enhancer, times(1)).enhance(accessToken);
        }

        @Test
        @DisplayName("설정된 Enhancer를 사용한 후 저장해야 한다.")
        void shouldSaveBeforeUsingEnhancer() {
            granter.grant(clientDetails, tokenRequest);

            InOrder inOrder = Mockito.inOrder(repository, enhancer);
            inOrder.verify(enhancer, times(1)).enhance(accessToken);
            inOrder.verify(repository, times(1)).save(accessToken);
        }

        @Nested
        @DisplayName("엑세스 토큰이 리플래시 토큰을 가지고 있지 않을시")
        class WhenAccessTokenNotHaveRefreshToken {

            @Test
            @DisplayName("리플래시 토큰은 null로 반환해야 한다.")
            void shouldReturnsRefreshTokenNull() {
                OAuth2AccessTokenDetails tokenDetails = granter.grant(clientDetails, tokenRequest);

                assertNull(tokenDetails.refreshToken());
            }
        }
    }
}