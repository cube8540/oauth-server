package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.APPROVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_APPROVED_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.STATE;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthorizationCode;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthorizationConsumer;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequest;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequestValidator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("인증 코드를 통한 토큰 부여 테스트")
class AuthorizationCodeGranterTest {

    @Nested
    @DisplayName("액세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("코드를 찾을 수 없을시")
        class WhenNotFoundAuthorizationCode extends AuthorizationCodeNotFoundSetup {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            @BeforeEach
            void setupParameter() {
                this.clientDetails = mockClientDetails().build();
                this.tokenRequest = mockTokenRequest().build();
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestExceptionAndErrorCodeIsInvalidRequest() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();

                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("코드를 찾을 수 있을시")
        class WhenFoundAuthorizationCode {

            @Nested
            @DisplayName("인증 코드에 저장된 스코프가 유효하지 않을시")
            class WhenAuthorizationCodeScopeIsNotAllowed extends AuthorizationCodeGranterSetup {

                @Override
                protected void configAuthorizationCode(OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode) {
                    mockAuthorizationCode.configDefault();
                }

                @Override
                protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest) {
                    mockTokenRequest.configDefaultCode().configDefaultScopes().configDefaultRedirectUri().configDefaultState();
                }

                @Override
                protected void configGranter(AuthorizationCodeTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationFalse(clientDetails, RAW_APPROVED_SCOPES).build();
                    granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
                void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidScope() {
                    OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                            .getError();

                    assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
                }
            }

            @Nested
            @DisplayName("인증 코드에 저장된 스코프가 유효할시")
            class WhenAuthorizationCodeScopeIsAllowed {

                @Nested
                @DisplayName("인증 코드에 스코프가 null 일시")
                class WhenAuthorizationCodeScopeIsNull extends AuthorizationCodeGranterSetup {

                    @Override
                    protected void configAuthorizationCode(OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode) {
                        mockAuthorizationCode.configDefault().configDefaultApprovalScopesNull();
                    }

                    @Override
                    protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest) {
                        mockTokenRequest.configDefaultCode().configDefaultScopes().configDefaultRedirectUri().configDefaultState();
                    }

                    @Override
                    protected void configGranter(AuthorizationCodeTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, null).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
                    void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidScope() {
                        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                                .getError();

                        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
                    }
                }

                @Nested
                @DisplayName("인증 코드에 스코프가 비어있을시")
                class WhenAuthorizationCodeScopeIsEmpty extends AuthorizationCodeGranterSetup {

                    @Override
                    protected void configAuthorizationCode(OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode) {
                        mockAuthorizationCode.configDefault().configDefaultApprovalScopesEmpty();
                    }

                    @Override
                    protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest) {
                        mockTokenRequest.configDefaultCode().configDefaultScopes().configDefaultRedirectUri().configDefaultState();
                    }

                    @Override
                    protected void configGranter(AuthorizationCodeTokenGranter granter) {
                        OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, Collections.emptySet()).build();
                        granter.setTokenRequestValidator(validator);
                    }

                    @Test
                    @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
                    void shouldThrowsInvalidGrantExceptionAndErrorCodeIsInvalidScope() {
                        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                                .getError();

                        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
                    }
                }

                @Nested
                @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있지 않을시")
                class WhenNotSetRefreshTokenIdGenerator extends AuthorizationCodeAssertSetup {
                    @Override
                    protected void configGranter(AuthorizationCodeTokenGranter granter) {
                        super.configGranter(granter);
                        granter.setRefreshTokenIdGenerator(null);
                    }

                    @Test
                    @DisplayName("리플래스 토큰의 아이디는 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }
                }

                @Nested
                @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
                class WhenSetRefreshTokenIdGenerator extends AuthorizationCodeAssertSetup {

                    @Override
                    protected void configGranter(AuthorizationCodeTokenGranter granter) {
                        super.configGranter(granter);
                        granter.setRefreshTokenIdGenerator(mockTokenIdGenerator(REFRESH_TOKEN_ID));
                    }

                    @Test
                    @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }
                }
            }
        }
    }

    private static abstract class AuthorizationCodeNotFoundSetup {
        protected AuthorizationCodeTokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2TokenIdGenerator generator = mockTokenIdGenerator(ACCESS_TOKEN_ID);
            OAuth2AccessTokenRepository repository = mockAccessTokenRepository().emptyAccessToken().build();
            OAuth2AuthorizationCodeConsumer consumer = mockAuthorizationConsumer().empty().build();

            this.granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);
        }
    }

    private static abstract class AuthorizationCodeGranterSetup {
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;
        protected OAuth2AuthorizationCode authorizationCode;
        protected AuthorizationCodeTokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2TokenApplicationTestHelper.MockClientDetails mockClientDetails = mockClientDetails().configDefault();
            OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest = mockTokenRequest();
            OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode = mockAuthorizationCode();
            OAuth2AccessTokenRepository repository = mockAccessTokenRepository().build();

            configClientDetails(mockClientDetails);
            configTokenRequest(mockTokenRequest);
            configAuthorizationCode(mockAuthorizationCode);

            this.clientDetails = mockClientDetails.build();
            this.tokenRequest = mockTokenRequest.build();
            this.authorizationCode = mockAuthorizationCode.build();
            this.granter = new AuthorizationCodeTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID),
                    repository, mockAuthorizationConsumer().consume(authorizationCode).build());

            configGranter(this.granter);
            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
        }

        protected void configClientDetails(OAuth2TokenApplicationTestHelper.MockClientDetails mockClientDetails) {}
        protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest) {}
        protected void configAuthorizationCode(OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode) {}
        protected void configGranter(AuthorizationCodeTokenGranter granter) {}
    }

    private static abstract class AuthorizationCodeAssertSetup extends AuthorizationCodeGranterSetup {

        @Override
        protected void configClientDetails(OAuth2TokenApplicationTestHelper.MockClientDetails mockClientDetails) {
            mockClientDetails.configDefault();
        }

        @Override
        protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest) {
            mockTokenRequest.configDefaultCode().configDefaultState().configDefaultRedirectUri();
        }

        @Override
        protected void configAuthorizationCode(OAuth2TokenApplicationTestHelper.MockAuthorizationCode mockAuthorizationCode) {
            mockAuthorizationCode.configDefault();
        }

        @Override
        protected void configGranter(AuthorizationCodeTokenGranter granter) {
            OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, RAW_APPROVED_SCOPES).build();
            granter.setTokenRequestValidator(validator);
        }

        @Test
        @DisplayName("인증 코드를 통해 요청 정보에 대한 유효성 검사를 해야 한다.")
        void shouldValidationTestViaAuthorizationCode() {
            ArgumentCaptor<AuthorizationRequest> requestCaptor = ArgumentCaptor.forClass(AuthorizationRequest.class);

            granter.createAccessToken(clientDetails, tokenRequest);
            verify(authorizationCode, times(1)).validateWithAuthorizationRequest(requestCaptor.capture());
            assertEquals(REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
            assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
            assertEquals(STATE, requestCaptor.getValue().getState());
        }

        @Test
        @DisplayName("토큰의 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
        void shouldTokenIdIsCreatedByTokenGenerator() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        }

        @Test
        @DisplayName("토큰의 클라이언트 아이디는 인증 코드에 저장된 클라이언트 아이디어야 한다.")
        void shouldClientIdIsSavedClientIdInAuthorizationCode() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(CLIENT_ID, accessToken.getClient());
        }

        @Test
        @DisplayName("토큰에 저장된 유저 아이디는 인증 코드에 저장된 유저어야 한다.")
        void shouldUserEmailIsSavedUserEmailInAuthorizationCode() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(USERNAME, accessToken.getUsername());
        }

        @Test
        @DisplayName("토큰에 저장된 스코프는 인증 코드에 저장된 스코프어야 한다.")
        void shouldScopeIsSavedScopeInAuthorizationCode() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(APPROVED_SCOPES, accessToken.getScopes());
        }

        @Test
        @DisplayName("토큰의 인증 타입은 AuthorizationCode 타입이어야 한다.")
        void shouldTokenGrantTypeIsAuthorizationCode() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, accessToken.getTokenGrantType());
        }

        @Test
        @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
        void shouldSetTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        }

        @Test
        @DisplayName("리플래시 토큰의 유효시간은 현재 시간에 클라이언트에 저장된 리플래시 토큰 유효시간을 더한 시간이어야 한다.")
        void shouldRefreshTokenExpirationIsCurrentTimePlusStoredInClientRefreshTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
        }
    }
}