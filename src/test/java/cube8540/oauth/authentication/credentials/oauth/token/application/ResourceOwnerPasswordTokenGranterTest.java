package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.UserDeniedAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.AUTHENTICATION_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAuthenticationManager;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequest;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequestValidator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("자원 소유자의 패스워드를 통한 토큰 부여 테스트")
class ResourceOwnerPasswordTokenGranterTest {

    @Nested
    @DisplayName("엑세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("요청 객체에서 유저 아이디를 찾을 수 없을시")
        class WhenNotfoundUsernameParameter {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            private ResourceOwnerPasswordTokenGranter granter;

            @BeforeEach
            void setup() {
                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configNullUsername().configDefaultPassword().build();

                this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID),
                        mockAccessTokenRepository().build(), mockAuthenticationManager().build());
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청 객체에서 패스워드를 찾을 수 없을시")
        class WhenNotfoundPasswordParameter {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            private ResourceOwnerPasswordTokenGranter granter;

            @BeforeEach
            void setup() {
                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configNullPassword().build();

                this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID),
                        mockAccessTokenRepository().build(), mockAuthenticationManager().build());
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청 받은 스코프가 유효하지 않을시")
        class WhenScopeNotAllowed {
            private OAuth2ClientDetails clientDetails;
            private OAuth2TokenRequest tokenRequest;

            private ResourceOwnerPasswordTokenGranter granter;

            @BeforeEach
            void setup() {
                this.clientDetails = mockClientDetails().configDefault().build();
                this.tokenRequest = mockTokenRequest().configDefaultScopes().configDefaultUsername().configDefaultPassword().build();

                this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID),
                        mockAccessTokenRepository().build(), mockAuthenticationManager().build());

                OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationFalse(clientDetails, RAW_SCOPES).build();
                this.granter.setTokenRequestValidator(validator);
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 INVALID_SCOPE 이어야 한다.")
            void shouldThrowsInvalidGrantException() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();

                assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청 정보가 유효할시")
        class WhenRequestParameterAllowed {

            @Nested
            @DisplayName("계정 인증에 실패했을시")
            class WhenAuthenticationFails {
                private OAuth2ClientDetails clientDetails;
                private OAuth2TokenRequest tokenRequest;

                private ResourceOwnerPasswordTokenGranter granter;

                @BeforeEach
                void setup() {
                    UsernamePasswordAuthenticationToken usernamePasswordToken =
                            new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
                    AuthenticationManager manager = mockAuthenticationManager().badCredentials(usernamePasswordToken).build();

                    this.clientDetails = mockClientDetails().configDefault().build();
                    this.tokenRequest = mockTokenRequest().configDefaultUsername().configDefaultPassword().configDefaultScopes().build();
                    this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID), mockAccessTokenRepository().build(), manager);

                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, RAW_SCOPES).build();
                    this.granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("UserDeniedAuthorizationException 이 발생해야 한다.")
                void shouldUserDeniedAuthorizationException() {
                    assertThrows(UserDeniedAuthorizationException.class, () -> granter.createAccessToken(clientDetails, tokenRequest));
                }
            }

            @Nested
            @DisplayName("계정 상태가 유효하지 않을시")
            class WhenAccountStatusNotAllowed {
                private OAuth2ClientDetails clientDetails;
                private OAuth2TokenRequest tokenRequest;

                private ResourceOwnerPasswordTokenGranter granter;

                @BeforeEach
                void setup() {
                    UsernamePasswordAuthenticationToken usernamePasswordToken =
                            new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
                    AuthenticationManager manager = mockAuthenticationManager().badAccountStatus(usernamePasswordToken).build();

                    this.clientDetails = mockClientDetails().configDefault().build();
                    this.tokenRequest = mockTokenRequest().configDefaultUsername().configDefaultPassword().configDefaultScopes().build();
                    this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID), mockAccessTokenRepository().build(), manager);

                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, RAW_SCOPES).build();
                    this.granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("UserDeniedAuthorizationException 이 발생해야 한다.")
                void shouldUserDeniedAuthorizationException() {
                    assertThrows(UserDeniedAuthorizationException.class, () -> granter.createAccessToken(clientDetails, tokenRequest));
                }
            }

            @Nested
            @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있을시")
            class WhenSetRefreshTokenId extends AccessGranterAssertSetup {

                @Override
                protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configDefaultUsername().configDefaultPassword().configNullScopes();
                }

                @Override
                protected void configGranter(ResourceOwnerPasswordTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, null).build();
                    granter.setTokenRequestValidator(validator);
                    granter.setRefreshTokenIdGenerator(mockTokenIdGenerator(REFRESH_TOKEN_ID));
                }

                @Test
                @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                }
            }

            @Nested
            @DisplayName("리플래시 토큰 아이디 생성자가 설정되어 있지 않을시")
            class WhenNotSetRefreshTokenId extends AccessGranterAssertSetup {

                @Override
                protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configDefaultUsername().configDefaultPassword().configNullScopes();
                }

                @Override
                protected void configGranter(ResourceOwnerPasswordTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, null).build();
                    granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("리플래스 토큰의 아이디는 리플래시 토큰 아이디 생성자가 생성한 아이디어야 한다.")
                void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                }
            }

            @Nested
            @DisplayName("요청 스코프가 null 일시")
            class WhenRequestScopeNull extends AccessGranterAssertSetup {

                @Override
                protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configDefaultUsername().configDefaultPassword().configNullScopes();
                }

                @Override
                protected void configGranter(ResourceOwnerPasswordTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, null).build();
                    granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("토큰의 스코프는 ClientDetails 에 저장된 스코프어야 한다.")
                void shouldScopeIsStoredInClientDetails() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(CLIENT_SCOPES, accessToken.getScopes());
                }
            }

            @Nested
            @DisplayName("요청 스코프가 비어있을시")
            class WhenRequestEmptyScope extends AccessGranterAssertSetup {

                @Override
                protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configDefaultUsername().configDefaultPassword().configEmptyScopes();
                }

                @Override
                protected void configGranter(ResourceOwnerPasswordTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, Collections.emptySet()).build();
                    granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("토큰의 스코프는 ClientDetails 에 저장된 스코프어야 한다.")
                void shouldScopeIsStoredInClientDetails() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(CLIENT_SCOPES, accessToken.getScopes());
                }
            }
        }
    }

    private static abstract class AccessGranterAssertSetup {
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;
        protected OAuth2AccessTokenRepository repository;

        protected ResourceOwnerPasswordTokenGranter granter;

        @BeforeEach
        void setup() {
            UsernamePasswordAuthenticationToken usernamePasswordToken =
                    new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
            AuthenticationManager manager = mockAuthenticationManager().authentication(usernamePasswordToken, mockAuthentication()).build();
            OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest = mockTokenRequest();

            configTokenRequest(tokenRequest);

            this.clientDetails = mockClientDetails().configDefault().build();
            this.tokenRequest = tokenRequest.build();
            this.repository = mockAccessTokenRepository().build();
            this.granter = new ResourceOwnerPasswordTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID), repository, manager);

            configGranter(granter);

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
        }

        protected void configTokenRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {}
        protected void configGranter(ResourceOwnerPasswordTokenGranter granter) {}

        @Test
        @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 아이디어야 한다.")
        void shouldTokenIdIsCreatedByTokenGenerator() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        }

        @Test
        @DisplayName("토큰의 클라이언트 아이디는 ClientDetails 에 저장된 클라이언트 아이디어야한다.")
        void shouldClientIdIsStoredInClientDetails() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(CLIENT_ID, accessToken.getClient());
        }

        @Test
        @DisplayName("토큰에 저장된 유저 아이디는 인증받은 유저의 아이디어야 한다.")
        void shouldUsernameIsAuthenticationUsername() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AUTHENTICATION_USERNAME, accessToken.getUsername());
        }

        @Test
        @DisplayName("토큰의 인증 타입은 자원 소유자 패스워드 인증 방식 이어야 한다.")
        void shouldGrantTypeIsResourceOwnerPasswordGrantType() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AuthorizationGrantType.PASSWORD, accessToken.getTokenGrantType());
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
    }
}
