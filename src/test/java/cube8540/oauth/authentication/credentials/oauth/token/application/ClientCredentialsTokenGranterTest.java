package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_TIME_ZONE;
import static cube8540.oauth.authentication.AuthenticationApplication.DEFAULT_ZONE_OFFSET;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.mockTokenRequestValidator;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("클라이언트 인증을 통한 토큰 부여 테스트")
class ClientCredentialsTokenGranterTest {

    @Nested
    @DisplayName("액세스 토큰 생성")
    class CreateAccessToken {

        @Nested
        @DisplayName("요청 받은 스코프가 유효하지 않을시")
        class WhenScopeNotAllowed extends AccessTokenGranterSetup {

            @Override
            protected void configGranter(ClientCredentialsTokenGranter granter) {
                OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationFalse(clientDetails, RAW_SCOPES).build();
                this.granter.setTokenRequestValidator(validator);
            }

            @Override
            protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                tokenRequest.configDefaultScopes();
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 InvalidScope 이어야 한다.")
            void shouldThrowsInvalidGrantException() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, tokenRequest))
                        .getError();

                assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청 받은 스코프가 유효할시")
        class WhenScopeAllowed {

            @Nested
            @DisplayName("요청 스코프가 null 일시")
            class WhenRequestScopeNull extends AccessTokenGranterAssertSetup {

                @Override
                protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configNullScopes();
                }

                @Override
                protected void configGranter(ClientCredentialsTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, null).build();
                    this.granter.setTokenRequestValidator(validator);
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
            class WhenRequestEmptyScope extends AccessTokenGranterAssertSetup {

                @Override
                protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
                    tokenRequest.configEmptyScopes();
                }

                @Override
                protected void configGranter(ClientCredentialsTokenGranter granter) {
                    OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, Collections.emptySet()).build();
                    this.granter.setTokenRequestValidator(validator);
                }

                @Test
                @DisplayName("토큰의 스코프는 ClientDetails 에 저장된 스코프어야 한다.")
                void shouldScopeIsStoredInClientDetails() {
                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                    assertEquals(CLIENT_SCOPES, accessToken.getScopes());
                }
            }

            @Nested
            @DisplayName("요청 스코프가 null 이 아니며 비어있지 않을시")
            class WhenRequestScopeNotNullAndNotEmpty extends AccessTokenGranterAssertSetup {

                @Test
                @DisplayName("토큰의 스코프는 토큰 요청 정보에 저장된 스코프이어야 한다.")
                void shouldScopeIsStoredInRequest() {
                    Set<OAuth2ScopeId> exceptedScopes = RAW_SCOPES.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

                    OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);
                    assertEquals(exceptedScopes, accessToken.getScopes());
                }
            }

            @Nested
            @DisplayName("리플래시 허용 여부가 true 일시")
            class WhenAllowedRefreshToken {

                @Nested
                @DisplayName("리플래스 토큰 아이디 생성기가 설정 되어 있지 않을시")
                class WhenNotSetRefreshTokenIdGenerator extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configGranter(ClientCredentialsTokenGranter granter) {
                        super.configGranter(granter);
                        granter.setAllowedRefreshToken(true);
                    }

                    @Test
                    @DisplayName("리플래시 토큰에 저장된 토큰 아이디는 토큰 아이디 생성기에서 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }

                    @Test
                    @DisplayName("리플래시 토큰의 유효시간은 현재 시간에 클라이언트에 저장된 리플래시 토큰 유효시간을 더한 시간이어야 한다.")
                    void shouldRefreshTokenExpirationIsCurrentTimePlusStoredInClientRefreshTokenValidity() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
                    }
                }

                @Nested
                @DisplayName("리플래스 토큰 아이디 생성기가 설정되어 있을시")
                class WhenSetRefreshTokenIdGenerator extends AccessTokenGranterAssertSetup {

                    @Override
                    protected void configGranter(ClientCredentialsTokenGranter granter) {
                        super.configGranter(granter);
                        granter.setRefreshTokenIdGenerator(mockTokenIdGenerator(REFRESH_TOKEN_ID));
                        granter.setAllowedRefreshToken(true);
                    }

                    @Test
                    @DisplayName("리플래시 토큰에 저장된 토큰 아이디는 리플래스 토큰 아이디 생성기에서 생성한 아이디어야 한다.")
                    void shouldRefreshTokenIdIsCreatedByRefreshTokenIdGenerator() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
                    }

                    @Test
                    @DisplayName("리플래시 토큰의 유효시간은 현재 시간에 클라이언트에 저장된 리플래시 토큰 유효시간을 더한 시간이어야 한다.")
                    void shouldRefreshTokenExpirationIsCurrentTimePlusStoredInClientRefreshTokenValidity() {
                        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

                        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
                    }
                }
            }
        }
    }

    private static abstract class AccessTokenGranterSetup {
        protected OAuth2ClientDetails clientDetails;
        protected OAuth2TokenRequest tokenRequest;

        protected ClientCredentialsTokenGranter granter;

        @BeforeEach
        void setup() {
            OAuth2TokenApplicationTestHelper.MockTokenRequest mockTokenRequest = OAuth2TokenApplicationTestHelper.mockTokenRequest();

            configRequest(mockTokenRequest);

            this.clientDetails = mockClientDetails().configDefault().build();
            this.tokenRequest = mockTokenRequest.build();
            this.granter = new ClientCredentialsTokenGranter(mockTokenIdGenerator(ACCESS_TOKEN_ID), mockAccessTokenRepository().build());

            Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(DEFAULT_ZONE_OFFSET), DEFAULT_TIME_ZONE.toZoneId());
            AbstractOAuth2TokenGranter.setClock(clock);
            configGranter(granter);
        }

        protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {}
        protected void configGranter(ClientCredentialsTokenGranter granter) {}
    }

    private static abstract class AccessTokenGranterAssertSetup extends AccessTokenGranterSetup {

        @Override
        protected void configRequest(OAuth2TokenApplicationTestHelper.MockTokenRequest tokenRequest) {
            tokenRequest.configDefaultScopes();
        }

        @Override
        protected void configGranter(ClientCredentialsTokenGranter granter) {
            OAuth2RequestValidator validator = mockTokenRequestValidator().configValidationTrue(clientDetails, RAW_SCOPES).build();
            this.granter.setTokenRequestValidator(validator);
        }

        @Test
        @DisplayName("토큰 아이디는 토큰 아이디 생성기에서 생성된 토큰 아이디어야 한다.")
        void shouldTokenIdIsCreatedByTokenIdGenerator() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        }

        @Test
        @DisplayName("토큰의 유저 이메일은 null 로 저장되어있어야 한다.")
        void shouldSetNullUserEmail() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertNull(accessToken.getUsername());
        }

        @Test
        @DisplayName("클라이언트 아이디는 ClientDetails 에 저장된 아이디어야 한다.")
        void shouldClientIdIsStoredInClientDetails() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(CLIENT_ID, accessToken.getClient());
        }

        @Test
        @DisplayName("토큰의 인증 타입은 Client Credentials 이어야 한다.")
        void shouldGrantTypeIsClientCredentials() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, accessToken.getTokenGrantType());
        }

        @Test
        @DisplayName("토큰의 유효시간이 설정되어 있어야 한다.")
        void shouldSetTokenValidity() {
            OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, tokenRequest);

            assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        }
    }
}