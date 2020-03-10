package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.APPROVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.NEW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.NEW_REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_APPROVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockRefreshToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockRefreshTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequest;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequestValidator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("리플레시 토큰을 통한 토큰 부여 테스트")
class RefreshTokenGranterTest {

    private static abstract class AccessTokenGranterAssertSetup {
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;
        protected OAuth2AuthorizedRefreshToken refreshToken;
        protected OAuth2RefreshTokenRepository repository;

        protected RefreshTokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().configScopes(APPROVED_SCOPES).build();
            OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest = mockTokenRequest().configDefaultRefreshToken();

            configRequest(tokenRequest);

            this.refreshToken = mockRefreshToken().configDefault().configAccessToken(accessToken).build();
            this.clientDetails = mockClientDetails().configDefault().build();
            this.tokenRequest = tokenRequest.build();
            this.repository = mockRefreshTokenRepository().registerRefreshToken(refreshToken).build();
            this.granter = new RefreshTokenGranter(mockAccessTokenRepository().build(), repository, mockTokenIdGenerator(NEW_ACCESS_TOKEN_ID));

            OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_CLIENT_SCOPES, RAW_SCOPES).build();
            granter.setTokenRequestValidator(validator);

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);

            configGranter(granter);
        }

        protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {}
        protected void configGranter(RefreshTokenGranter granter) {}

        @Test
        @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
        void shouldTokenIdIsCreatedByTokenGenerator() {
            OAuth2AuthorizedAccessToken result = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(NEW_ACCESS_TOKEN_ID, result.getTokenId());
        }

        @Test
        @DisplayName("토큰의 클라이언트 아이디는 검색된 토큰의 클라이언트 아이디어야 한다.")
        void shouldClientIdIsSearchedAccessTokensClientId() {
            OAuth2AuthorizedAccessToken result = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(CLIENT_ID, result.getClient());
        }

        @Test
        @DisplayName("토큰에 저장된 유저 아이디는 검색된 토큰의 유저 아이디어야 한다.")
        void shouldUserEmailIsSearchedAccessTokensUserEmail() {
            OAuth2AuthorizedAccessToken result = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(USERNAME, result.getUsername());
        }

        @Test
        @DisplayName("토큰의 인증 타입은 검색된 토큰의 인증 타입이어야 한다.")
        void shouldAuthorizedGrantTypeIsSearchedAccessTokensGrantType() {
            OAuth2AuthorizedAccessToken result = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, result.getTokenGrantType());
        }

        @Test
        @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
        void shouldSetTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        }

        @Test
        @DisplayName("리플래시 토큰의 유효시간이 설정되어 있어야 한다.")
        void shouldSetRefreshTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
        }

        @Test
        @DisplayName("검색된 리플레시 토큰을 삭제해야 한다.")
        void shouldRemoveSearchedRefreshToken() {
            granter.createAccessToken(clientDetails, tokenRequest);

            verify(repository, times(1)).delete(refreshToken);
        }
    }

    @Nested
    @DisplayName("엑세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("리플레시 토큰을 찾을 수 없을시")
        class WhenRefreshTokenNotFound {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            private RefreshTokenGranter granter;

            @BeforeEach
            void setup() {
                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configDefaultRefreshToken().build();
                this.granter = new RefreshTokenGranter(mockAccessTokenRepository().build(),
                        mockRefreshTokenRepository().emptyRefreshToken().build(), mockTokenIdGenerator(ACCESS_TOKEN_ID));
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_GRANT 이어야 한다.")
            void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidGrant() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();

                assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("리플레시 토큰이 만료되었을시")
        class WhenRefreshTokenExpired {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;
            private OAuth2AuthorizedRefreshToken refreshToken;
            private OAuth2RefreshTokenRepository repository;

            private RefreshTokenGranter granter;

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().build();

                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configDefaultRefreshToken().build();
                this.refreshToken = mockRefreshToken().configDefault().configAccessToken(accessToken).configExpired().build();
                this.repository = mockRefreshTokenRepository().registerRefreshToken(refreshToken).build();
                this.granter = new RefreshTokenGranter(mockAccessTokenRepository().build(), repository, mockTokenIdGenerator(ACCESS_TOKEN_ID));
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest));
            }

            @Test
            @DisplayName("리플래시 토큰을 삭제해야 한다.")
            void shouldRemoveRefreshToken() {
                assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest));

                verify(repository, times(1)).delete(refreshToken);
            }
        }

        @Nested
        @DisplayName("리플레시 토큰을 할당 받은 클라이언트와 현재 요청을 한 클라이언트가 서로 다를시")
        class WhenRefreshTokenClientIsNotThisRequestingClient {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;
            private OAuth2RefreshTokenRepository repository;

            private RefreshTokenGranter granter;

            @BeforeEach
            void setup() {
                OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().configMismatchesClientId().build();
                OAuth2AuthorizedRefreshToken refreshToken = mockRefreshToken().configDefault().configAccessToken(accessToken).build();

                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configDefaultRefreshToken().build();
                this.repository = mockRefreshTokenRepository().registerRefreshToken(refreshToken).build();
                this.granter = new RefreshTokenGranter(mockAccessTokenRepository().build(), repository, mockTokenIdGenerator(ACCESS_TOKEN_ID));
            }

            @Test
            @DisplayName("InvalidClientException 이 발생해야 하며 에러 코드는 INVALID_CLIENT 이어야 한다.")
            void shouldThrowsInvalidClientExceptionAndErrorCodeIsInvalidClient() {
                OAuth2Error error = assertThrows(InvalidClientException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();

                assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
            }

            @Test
            @DisplayName("검색된 리플레시 토큰을 삭제하지 않아야 한다.")
            void shouldNotRemoveRefreshToken() {
                verify(repository, never()).delete(any());
            }
        }

        @Nested
        @DisplayName("리플레시 토큰이 유효할시")
        class WhenRefreshTokenIsValid {

            @Nested
            @DisplayName("요청한 스코프가 유효하지 않을시")
            class WhenRequestScopeNotAllowed {
                private OAuth2ClientDetails clientDetails;
                private OAuth2TokenRequest tokenRequest;

                private RefreshTokenGranter granter;

                @BeforeEach
                void setup() {
                    OAuth2AuthorizedAccessToken accessToken = mockAccessToken().configDefault().build();
                    OAuth2AuthorizedRefreshToken refreshToken = mockRefreshToken().configDefault().configAccessToken(accessToken).build();

                    this.clientDetails = mockClientDetails().configDefault().build();
                    this.tokenRequest = mockTokenRequest().configDefaultScopes().configDefaultRefreshToken().build();
                    this.granter = new RefreshTokenGranter(mockAccessTokenRepository().build(),
                            mockRefreshTokenRepository().registerRefreshToken(refreshToken).build(), mockTokenIdGenerator(ACCESS_TOKEN_ID));

                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationFalse(RAW_CLIENT_SCOPES, RAW_SCOPES).build();
                    granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("InvalidGrantException 예외가 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
                void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidScope() {
                    OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                            .getError();

                    assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
                }
            }

            @Nested
            @DisplayName("요청한 스코프가 유효할시")
            class WhenRequestScopeAllowed {

                @Nested
                @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있지 않을시")
                class WhenNotSetRefreshTokenId extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                        tokenRequest.configDefaultScopes();
                    }

                    @Override
                    protected void configGranter(RefreshTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_APPROVED_SCOPES, RAW_SCOPES).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("리플래스 토큰의 아이디는 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(NEW_ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }
                }

                @Nested
                @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
                class WhenSetRefreshTokenId extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                        tokenRequest.configDefaultScopes();
                    }

                    @Override
                    protected void configGranter(RefreshTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_APPROVED_SCOPES, RAW_SCOPES).build();
                        granter.setRefreshTokenIdGenerator(mockTokenIdGenerator(NEW_REFRESH_TOKEN_ID));
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(NEW_REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }
                }

                @Nested
                @DisplayName("요청 스코프가 null 일시")
                class WhenRequestScopeNull extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                        tokenRequest.configNullScopes();
                    }

                    @Override
                    protected void configGranter(RefreshTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_APPROVED_SCOPES, null).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 액세스 토큰에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(APPROVED_SCOPES, accessToken.getScopes());
                    }
                }

                @Nested
                @DisplayName("요청 스코프가 비어있을시")
                class WhenRequestEmptyScope extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                        tokenRequest.configEmptyScopes();
                    }

                    @Override
                    protected void configGranter(RefreshTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_APPROVED_SCOPES, Collections.emptySet()).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 액세스 토큰에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInClientDetails() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(APPROVED_SCOPES, accessToken.getScopes());
                    }
                }

                @Nested
                @DisplayName("요청 스코프가 null 이지 않고 비어있지도 않을시")
                class WhenRequestScopeNotNullAndNotEmpty extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                        tokenRequest.configDefaultScopes();
                    }

                    @Override
                    protected void configGranter(RefreshTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(RAW_APPROVED_SCOPES, RAW_SCOPES).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("토큰의 스코프는 요청 객체에 저장된 스코프어야 한다.")
                    void shouldScopeIsStoredInRequestingObject() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(SCOPES, accessToken.getScopes());
                    }
                }
            }
        }
    }
}