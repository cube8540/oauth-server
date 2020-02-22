package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증을 통한 토큰 부여 테스트")
class ClientCredentialsTokenGranterTest {

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final LocalDateTime TOKEN_CREATED_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 57);

    private static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    private static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    private static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("CODE-1", "CODE-2", "CODE-3"));
    private static final Set<String> CLIENT_SCOPE = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));

    private OAuth2TokenIdGenerator tokenIdGenerator;
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private ClientCredentialsTokenGranter tokenGranter;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        OAuth2AccessTokenRepository accessTokenRepository = mock(OAuth2AccessTokenRepository.class);
        this.refreshTokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        this.tokenGranter = new ClientCredentialsTokenGranter(tokenIdGenerator, accessTokenRepository);
    }

    @Nested
    @DisplayName("액세스 토큰 생성")
    class CreateAccessToken {

        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        private OAuth2RequestValidator validator;

        @BeforeEach
        void setup() {
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenRequest = mock(OAuth2TokenRequest.class);
            this.validator = mock(OAuth2RequestValidator.class);

            when(clientDetails.clientId()).thenReturn(RAW_CLIENT_ID);
            when(clientDetails.scope()).thenReturn(CLIENT_SCOPE);
            when(clientDetails.accessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
            when(clientDetails.refreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);
            when(tokenRequest.scopes()).thenReturn(RAW_SCOPES);

            tokenGranter.setTokenRequestValidator(validator);

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
        }

        @Nested
        @DisplayName("요청 받은 스코프가 유효하지 않을시")
        class WhenScopeNotAllowed {

            @BeforeEach
            void setup() {
                when(validator.validateScopes(clientDetails, RAW_SCOPES)).thenReturn(false);
            }

            @Test
            @DisplayName("InvalidGrantException이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_SCOPE 이어야 한다.")
            void shouldErrorCodeIsInvalidScope() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청 받은 스코프가 유효할시")
        class WhenScopeAllowed {

            @BeforeEach
            void setup() {
                when(validator.validateScopes(clientDetails, RAW_SCOPES)).thenReturn(true);
                when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);
            }

            @Test
            @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
            void shouldTokenIdIsCreatedByTokenIdGenerator() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_ID, accessToken.getTokenId());
            }

            @Test
            @DisplayName("토큰의 유저 이메일은 null로 저장되어있어야 한다.")
            void shouldSetNullUserEmail() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertNull(accessToken.getEmail());
            }

            @Test
            @DisplayName("클라이언트 아이디는 ClientDetails에 저장된 아이디어야 한다.")
            void shouldClientIdIsStoredInClientDetails() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(CLIENT_ID, accessToken.getClient());
            }

            @Test
            @DisplayName("토큰의 인증 타입은 Client Credentials이어야 한다.")
            void shouldGrantTypeIsClientCredentials() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, accessToken.getTokenGrantType());
            }

            @Test
            @DisplayName("토큰의 스코프는 토큰 요청 정보에 저장된 스코프이어야 한다.")
            void shouldScopeIsStoredInRequest() {
                Set<OAuth2ScopeId> exceptedScopes = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                assertEquals(exceptedScopes, accessToken.getScope());
            }

            @Test
            @DisplayName("리플래시 토큰은 저장되 있지 않아야 한다.")
            void shouldRefreshTokenNull() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertNull(accessToken.getRefreshToken());
            }

            @Test
            @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
            void shouldSetTokenValidity() {
                OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
            }

            @Nested
            @DisplayName("요청 스코프가 null이거나 비어있을시")
            class WhenRequestScopeNullOrEmpty {

                @Nested
                @DisplayName("요청 스코프가 null일시")
                class WhenRequestScopeNull {
                    @BeforeEach
                    void setup() {
                        when(tokenRequest.scopes()).thenReturn(null);
                        when(validator.validateScopes(clientDetails, null)).thenReturn(true);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 ClientDetails에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        Set<OAuth2ScopeId> exceptedScopes = CLIENT_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                        assertEquals(exceptedScopes, accessToken.getScope());
                    }
                }

                @Nested
                @DisplayName("요청 스코프가 비어있을시")
                class WhenRequestEmptyScope {
                    @BeforeEach
                    void setup() {
                        when(tokenRequest.scopes()).thenReturn(Collections.emptySet());
                        when(validator.validateScopes(clientDetails, Collections.emptySet())).thenReturn(true);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 ClientDetails에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        Set<OAuth2ScopeId> exceptedScopes = CLIENT_SCOPE.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                        assertEquals(exceptedScopes, accessToken.getScope());
                    }
                }
            }

            @Nested
            @DisplayName("리플래시 허용 여부가 true일시")
            class WhenAllowedRefreshToken {
                @BeforeEach
                void setup() {
                    tokenGranter.setAllowedRefreshToken(true);
                }

                @Test
                @DisplayName("리플래스 토큰에 저장된 토큰 아이디는 토큰 아이디 생성기에서 생성한 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                }

                @Test
                @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
                void shouldSetTokenValidity() {
                    OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
                }

                @Nested
                @DisplayName("리플래스 토큰 아이디 생성기가 설정되어 있을시")
                class WhenSetRefreshTokenIdGenerator {

                    @BeforeEach
                    void setup() {
                        when(refreshTokenIdGenerator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
                        tokenGranter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);
                    }

                    @Test
                    @DisplayName("리플래시 토큰에 저장된 토큰 아이디는 리플래스 토큰 아이디 생성기에서 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }

                    @AfterEach
                    void after() {
                        tokenGranter.setRefreshTokenIdGenerator(null);
                    }
                }

                @AfterEach
                void after() {
                    tokenGranter.setAllowedRefreshToken(false);
                }
            }
        }
    }

}