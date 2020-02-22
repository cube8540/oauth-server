package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
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
import java.util.Optional;
import java.util.Set;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("리플레시 토큰을 통한 토큰 부여 테스트")
class RefreshTokenGranterTest {

    private static final String RAW_TOKEN_ID = "TOKEN-ID";
    private static final OAuth2TokenId TOKEN_ID = new OAuth2TokenId(RAW_TOKEN_ID);

    private static final String RAW_NEW_TOKEN_ID = "NEW-TOKEN-ID";
    private static final OAuth2TokenId NEW_TOKEN_ID = new OAuth2TokenId(RAW_NEW_TOKEN_ID);

    private static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    private static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    private static final String RAW_NEW_REFRESH_TOKEN_ID = "NEW-REFRESH-TOKEN-ID";
    private static final OAuth2TokenId NEW_REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_NEW_REFRESH_TOKEN_ID);

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String RAW_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final LocalDateTime TOKEN_CREATED_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 57);

    private static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 600;
    private static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 6000;

    private static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("CODE-1", "CODE-2", "CODE-3"));
    private static final Set<String> RAW_STORED_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    private static final Set<OAuth2ScopeId> STORED_SCOPES = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("SCOPE-1"),
            new OAuth2ScopeId("SCOPE-2"),
            new OAuth2ScopeId("SCOPE-3")
    ));

    private static final Set<OAuth2ScopeId> REQUESTED_SCOPE = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("CODE-1"),
            new OAuth2ScopeId("CODE-2"),
            new OAuth2ScopeId("CODE-3")
    ));

    private OAuth2TokenIdGenerator tokenIdGenerator;
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private OAuth2RefreshTokenRepository refreshTokenRepository;
    private RefreshTokenGranter tokenGranter;

    @BeforeEach
    void setup() {
        this.tokenIdGenerator = mock(OAuth2TokenIdGenerator.class);
        OAuth2AccessTokenRepository accessTokenRepository = mock(OAuth2AccessTokenRepository.class);
        this.refreshTokenIdGenerator = mock(OAuth2TokenIdGenerator.class);

        this.refreshTokenRepository = mock(OAuth2RefreshTokenRepository.class);
        this.tokenGranter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, tokenIdGenerator);
    }

    @Nested
    @DisplayName("엑세스 토큰 생성")
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
            when(clientDetails.accessTokenValiditySeconds()).thenReturn(ACCESS_TOKEN_VALIDITY_SECONDS);
            when(clientDetails.refreshTokenValiditySeconds()).thenReturn(REFRESH_TOKEN_VALIDITY_SECONDS);
            when(tokenRequest.scopes()).thenReturn(RAW_SCOPES);
            when(tokenIdGenerator.generateTokenValue()).thenReturn(TOKEN_ID);

            when(tokenRequest.refreshToken()).thenReturn(RAW_REFRESH_TOKEN_ID);

            tokenGranter.setTokenRequestValidator(validator);

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
        }

        @Nested
        @DisplayName("리플레시 토큰을 찾을 수 없을시")
        class WhenRefreshTokenNotFound {

            @BeforeEach
            void setup() {
                when(refreshTokenRepository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("InvalidGrantException이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                InvalidGrantException e = assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                assertEquals("invalid refresh token", e.getMessage());
            }

            @Test
            @DisplayName("에러 코드는 INVALID_GRANT 이어야 한다.")
            void shouldErrorCodeIsInvalidGrant() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("리플레시 토큰이 만료되었을시")
        class WhenRefreshTokenExpired {
            OAuth2AuthorizedRefreshToken refreshToken = mock(OAuth2AuthorizedRefreshToken.class);

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);

                when(refreshToken.isExpired()).thenReturn(true);
                when(refreshToken.getAccessToken()).thenReturn(accessToken);
                when(accessToken.getClient()).thenReturn(CLIENT_ID);
                when(refreshTokenRepository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.of(refreshToken));
            }

            @Test
            @DisplayName("InvalidGrantException이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                InvalidGrantException e = assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                assertEquals("refresh token is expired", e.getMessage());
            }

            @Test
            @DisplayName("리플래시 토큰을 삭제해야 한다.")
            void shouldRemoveRefreshToken() {
                assertThrows(InvalidGrantException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));

                verify(refreshTokenRepository, times(1)).delete(refreshToken);
            }
        }

        @Nested
        @DisplayName("리플레시 토큰을 할당 받은 클라이언트와 현재 요청을 한 클라이언트가 서로 다를시")
        class WhenRefreshTokenClientIsNotThisRequestingClient {

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);
                OAuth2AuthorizedRefreshToken refreshToken = mock(OAuth2AuthorizedRefreshToken.class);

                when(refreshToken.isExpired()).thenReturn(false);
                when(refreshToken.getAccessToken()).thenReturn(accessToken);
                when(accessToken.getClient()).thenReturn(new OAuth2ClientId("DIFFERENT_CLIENT"));
                when(refreshTokenRepository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.of(refreshToken));
            }

            @Test
            @DisplayName("InvalidClientException이 발생해야 한다.")
            void shouldThrowsInvalidClientException() {
                InvalidClientException e = assertThrows(InvalidClientException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                assertEquals("invalid refresh token", e.getMessage());
            }

            @Test
            @DisplayName("검색된 리플레시 토큰을 삭제하지 않아야 한다.")
            void shouldNotRemoveRefreshToken() {
                assertThrows(InvalidClientException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest));
                verify(refreshTokenRepository, never()).delete(any());
            }

            @Test
            @DisplayName("에러 코드는 INVALID_CLIENT 이어야 한다.")
            void shouldErrorCodeIsInvalidClient() {
                OAuth2Error error = assertThrows(InvalidClientException.class, () -> tokenGranter.createAccessToken(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("리플레시 토큰이 유효할시")
        class WhenRefreshTokenIsValid {
            private OAuth2AuthorizedRefreshToken refreshToken;

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);
                this.refreshToken = mock(OAuth2AuthorizedRefreshToken.class);

                when(refreshToken.getAccessToken()).thenReturn(accessToken);
                when(refreshToken.isExpired()).thenReturn(false);
                when(accessToken.getTokenId()).thenReturn(TOKEN_ID);
                when(accessToken.getClient()).thenReturn(CLIENT_ID);
                when(accessToken.getEmail()).thenReturn(EMAIL);
                when(accessToken.getTokenGrantType()).thenReturn(AuthorizationGrantType.AUTHORIZATION_CODE);
                when(accessToken.getScope()).thenReturn(STORED_SCOPES);

                when(tokenIdGenerator.generateTokenValue()).thenReturn(NEW_TOKEN_ID);
                when(refreshTokenIdGenerator.generateTokenValue()).thenReturn(NEW_REFRESH_TOKEN_ID);

                when(refreshTokenRepository.findById(REFRESH_TOKEN_ID)).thenReturn(Optional.of(refreshToken));
            }

            @Nested
            @DisplayName("요청한 스코프가 유효하지 않을시")
            class WhenRequestScopeNotAllowed {

                @BeforeEach
                void setup() {
                    when(validator.validateScopes(RAW_STORED_SCOPES, RAW_SCOPES)).thenReturn(false);
                }

                @Test
                @DisplayName("InvalidGrantException 예외가 발생해야 한다.")
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
            @DisplayName("요청한 스코프가 유효할시")
            class WhenRequestScopeAllowed {

                @BeforeEach
                void setup() {
                    when(validator.validateScopes(RAW_STORED_SCOPES, RAW_SCOPES)).thenReturn(true);
                }

                @Test
                @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
                void shouldTokenIdIsCreatedByTokenGenerator() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(NEW_TOKEN_ID, result.getTokenId());
                }

                @Test
                @DisplayName("토큰의 클라이언트 아이디는 검색된 토큰의 클라이언트 아이디어야 한다.")
                void shouldClientIdIsSearchedAccessTokensClientId() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(CLIENT_ID, result.getClient());
                }

                @Test
                @DisplayName("토큰에 저장된 유저 아이디는 검색된 토큰의 유저 아이디어야 한다.")
                void shouldUserEmailIsSearchedAccessTokensUserEmail() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(EMAIL, result.getEmail());
                }

                @Test
                @DisplayName("토큰에 저장된 스코프는 요청 객체에 담긴 스코프어야 한다.")
                void shouldScopeIsRequestedScope() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(REQUESTED_SCOPE, result.getScope());
                }

                @Test
                @DisplayName("토큰의 인증 타입은 검색된 토큰의 인증 타입이어야 한다.")
                void shouldAuthorizedGrantTypeIsSearchedAccessTokensGrantType() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, result.getTokenGrantType());
                }

                @Test
                @DisplayName("리플레시 토큰 아이디는 토큰 아이디 생성기에서 생성된 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken result = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(NEW_TOKEN_ID, result.getRefreshToken().getTokenId());
                }

                @Test
                @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
                void shouldSetTokenValidity() {
                    OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
                }

                @Test
                @DisplayName("리플래시 토큰의 유효시간이 설정되어 있어야 한다.")
                void shouldSetRefreshTokenValidity() {
                    OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
                }

                @Test
                @DisplayName("검색된 리플레시 토큰을 삭제해야 한다.")
                void shouldRemoveSearchedRefreshToken() {
                    tokenGranter.createAccessToken(clientDetails, tokenRequest);

                    verify(refreshTokenRepository, times(1)).delete(refreshToken);
                }

                @Nested
                @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
                class WhenSetRefreshTokenId {

                    @BeforeEach
                    void setup() {
                        tokenGranter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);
                    }

                    @Test
                    @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(NEW_REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }

                    @AfterEach
                    void after() {
                        tokenGranter.setRefreshTokenIdGenerator(null);
                    }
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
                            when(validator.validateScopes(RAW_STORED_SCOPES, null)).thenReturn(true);
                        }

                        @Test
                        @DisplayName("토큰의 스코프는 액세스 토큰에 저장된 스코프어야 한다.")
                        void shouldScopeIsStoredInClientDetails() {
                            OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                            assertEquals(STORED_SCOPES, accessToken.getScope());
                        }
                    }

                    @Nested
                    @DisplayName("요청 스코프가 비어있을시")
                    class WhenRequestEmptyScope {
                        @BeforeEach
                        void setup() {
                            when(tokenRequest.scopes()).thenReturn(Collections.emptySet());
                            when(validator.validateScopes(RAW_STORED_SCOPES, Collections.emptySet())).thenReturn(true);
                        }

                        @Test
                        @DisplayName("토큰의 스코프는 액세스 토큰에 저장된 스코프어야 한다.")
                        void shouldScopeIsStoredInClientDetails() {
                            OAuth2AuthorizedAccessToken accessToken = tokenGranter.createAccessToken(clientDetails, tokenRequest);
                            assertEquals(STORED_SCOPES, accessToken.getScope());
                        }
                    }
                }
            }
        }
    }
}