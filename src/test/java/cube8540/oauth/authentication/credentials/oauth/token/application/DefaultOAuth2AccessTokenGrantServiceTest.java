package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 부여 서비스 테스트")
class DefaultOAuth2AccessTokenGrantServiceTest {

    private static final String RAW_TOKEN_ID = "TOKEN_ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH_TOKEN_ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_CLIENT = "CLIENT";
    private static final OAuth2ClientId CLIENT = new OAuth2ClientId(RAW_CLIENT);

    private static final Set<String> RAW_SCOPE = new HashSet<>(Arrays.asList("SCOPE_1", "SCOPE_2", "SCOPE_3"));
    private static final Set<OAuth2ScopeId> SCOPE = RAW_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    private static final LocalDateTime EXPIRATION = LocalDateTime.of(2020, 1, 24, 21, 24, 0);
    private static final long EXPIRATION_IN = 600000;

    private static final LocalDateTime REFRESH_TOKEN_EXPIRATION = LocalDateTime.of(2020, 1, 24, 22, 24, 0);
    private static final long REFRESH_EXPIRATION_IN = 12000000;

    private static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    private static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    private static final boolean IS_EXPIRED = true;
    private static final boolean IS_REFRESH_TOKEN_EXPIRED = true;

    private OAuth2AccessTokenRepository accessTokenRepository;
    private OAuth2TokenFactory tokenFactory;

    private DefaultOAuth2AccessTokenGrantService grantService;

    @BeforeEach
    void setup() {
        this.accessTokenRepository = mock(OAuth2AccessTokenRepository.class);
        this.tokenFactory = mock(OAuth2TokenFactory.class);
        this.grantService = new DefaultOAuth2AccessTokenGrantService(accessTokenRepository, tokenFactory);
    }

    @Nested
    @DisplayName("엑세스 토큰 부여")
    class GrantAccessToken {
        private OAuth2AuthorizedAccessToken accessToken;
        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        @BeforeEach
        void setup() {
            this.accessToken = mock(OAuth2AuthorizedAccessToken.class);
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);

            when(clientDetails.clientId()).thenReturn(RAW_CLIENT);
            when(accessToken.getTokenId()).thenReturn(TOKEN_ID);
            when(accessToken.getEmail()).thenReturn(EMAIL);
            when(accessToken.getClient()).thenReturn(CLIENT);
            when(accessToken.getScope()).thenReturn(SCOPE);
            when(accessToken.getExpiration()).thenReturn(EXPIRATION);
            when(accessToken.getTokenGrantType()).thenReturn(GRANT_TYPE);
            when(accessToken.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
            when(accessToken.expiresIn()).thenReturn(EXPIRATION_IN);
            when(accessToken.isExpired()).thenReturn(IS_EXPIRED);
            when(tokenFactory.createAccessToken(clientDetails, tokenRequest)).thenReturn(accessToken);
        }

        @Test
        @DisplayName("팩토리에서 생성된 엑세스 토큰을 저장해야 한다.")
        void shouldSaveAccessTokenCreatedByFactory() {
            grantService.grant(clientDetails, tokenRequest);

            verify(accessTokenRepository, times(1)).save(accessToken);
        }

        @Nested
        @DisplayName("엑세스 토큰의 소유자가 요청한 클라이언트로 이미 인증을 받은 상태일시")
        class WhenAccessTokenUserAlreadyAuthenticationByRequestingClient {

            private OAuth2AuthorizedAccessToken existsToken;

            @BeforeEach
            void setup() {
                this.existsToken = mock(OAuth2AuthorizedAccessToken.class);

                when(accessTokenRepository.findByClientAndEmail(CLIENT, EMAIL)).thenReturn(Optional.of(existsToken));
            }

            @Test
            @DisplayName("저장소에서 반환된 엑세스 토큰을 삭제해야 한다.")
            void shouldRemoveReturnsAccessToken() {
                grantService.grant(clientDetails, tokenRequest);

                verify(accessTokenRepository, times(1)).delete(existsToken);
            }

            @AfterEach
            void after() {
                when(accessTokenRepository.findByClientAndEmail(any(), any())).thenReturn(Optional.empty());
            }
        }

        @Test
        @DisplayName("토큰의 아이디를 반환해야 한다.")
        void shouldReturnsTokenId() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(RAW_TOKEN_ID, tokenDetails.tokenValue());
        }

        @Test
        @DisplayName("토큰의 유저 아이디를 반환해야 한다.")
        void shouldReturnsUsername() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(RAW_EMAIL, tokenDetails.username());
        }

        @Test
        @DisplayName("토큰의 클라이언트 아이디를 반환해야 한다.")
        void shouldReturnsClientId() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(CLIENT, tokenDetails.clientId());
        }

        @Test
        @DisplayName("토큰의 스코프를 반환해야 한다.")
        void shouldReturnsScope() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(SCOPE, tokenDetails.scope());
        }

        @Test
        @DisplayName("토큰의 타입은 Bearer이어야 한다.")
        void shouldTokenTypeMustBearer() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals("Bearer", tokenDetails.tokenType());
        }

        @Test
        @DisplayName("토큰의 추가 정보를 반환해야 한다.")
        void shouldReturnsAdditionalInformation() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(ADDITIONAL_INFO, tokenDetails.additionalInformation());
        }

        @Test
        @DisplayName("토큰의 유효 시간을 반환해야 한다.")
        void shouldReturnsExpiration() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(EXPIRATION, tokenDetails.expiration());
        }

        @Test
        @DisplayName("토큰의 남은 유효 시간을 반환해야 한다.")
        void shouldReturnsExpirationIn() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(EXPIRATION_IN, tokenDetails.expiresIn());
        }

        @Test
        @DisplayName("토큰의 만료 여부를 반환해야 한다.")
        void shouldReturnsWhetherExpiredOrNot() {
            OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

            assertEquals(IS_EXPIRED, tokenDetails.isExpired());
        }

        @Nested
        @DisplayName("엑세스 토큰이 리플래시 토큰을 가지고 있지 않을시")
        class WhenAccessTokenNotHaveRefreshToken {

            @Test
            @DisplayName("리플래시 토큰은 null로 반환해야 한다.")
            void shouldReturnsRefreshTokenNull() {
                OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

                assertNull(tokenDetails.refreshToken());
            }
        }

        @Nested
        @DisplayName("엑세스 토큰이 리플래시 토큰을 가지고 있을시")
        class WhenAccessTokenHaveRefreshToken {

            @BeforeEach
            void setup() {
                OAuth2AuthorizedRefreshToken refreshToken = mock(OAuth2AuthorizedRefreshToken.class);

                when(accessToken.getRefreshToken()).thenReturn(refreshToken);
                when(refreshToken.getTokenId()).thenReturn(REFRESH_TOKEN_ID);
                when(refreshToken.getExpiration()).thenReturn(REFRESH_TOKEN_EXPIRATION);
                when(refreshToken.expiresIn()).thenReturn(REFRESH_EXPIRATION_IN);
                when(refreshToken.isExpired()).thenReturn(IS_REFRESH_TOKEN_EXPIRED);
            }

            @Test
            @DisplayName("리플래시 토큰의 아이디를 반환해야 한다.")
            void shouldReturnsRefreshTokenId() {
                OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

                assertEquals(RAW_REFRESH_TOKEN_ID, tokenDetails.refreshToken().tokenValue());
            }

            @Test
            @DisplayName("리플래시 토큰의 만료일을 반환해야 한다.")
            void shouldReturnsRefreshTokenExpiration() {
                OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

                assertEquals(REFRESH_TOKEN_EXPIRATION, tokenDetails.refreshToken().expiration());
            }

            @Test
            @DisplayName("리플래시 토큰의 만료 여부를 반환해야 한다.")
            void shouldRefreshTokenWhetherExpiredOrNot() {
                OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

                assertEquals(IS_REFRESH_TOKEN_EXPIRED, tokenDetails.isExpired());
            }

            @Test
            @DisplayName("리플래시 토큰의 남은 시간을 반환해야 한다.")
            void shouldRefreshTokenExpiresIn() {
                OAuth2AccessTokenDetails tokenDetails = grantService.grant(clientDetails, tokenRequest);

                assertEquals(REFRESH_EXPIRATION_IN, tokenDetails.refreshToken().expiresIn());
            }
        }

        @Nested
        @DisplayName("토큰 Enhancer가 설정되어 있을시")
        class WhenSetTokenEnhancer {
            private OAuth2TokenEnhancer enhancer;

            @BeforeEach
            void setup() {
                this.enhancer = mock(OAuth2TokenEnhancer.class);
                grantService.setEnhancer(enhancer);
            }

            @Test
            @DisplayName("설정된 Enhancer를 사용해야 한다.")
            void shouldUsingEnhancer() {
                grantService.grant(clientDetails, tokenRequest);

                verify(enhancer, times(1)).enhance(accessToken);
            }

            @Test
            @DisplayName("설정된 Enhancer를 사용한 후 저장해야 한다.")
            void shouldSaveBeforeUsingEnhancer() {
                grantService.grant(clientDetails, tokenRequest);

                InOrder inOrder = Mockito.inOrder(accessTokenRepository, enhancer);
                inOrder.verify(enhancer, times(1)).enhance(accessToken);
                inOrder.verify(accessTokenRepository, times(1)).save(accessToken);
            }
        }
    }

}