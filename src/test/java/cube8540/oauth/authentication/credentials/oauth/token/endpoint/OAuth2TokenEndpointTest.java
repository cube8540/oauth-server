package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.security.endpoint.OAuth2TokenEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.Principal;
import java.util.Map;

import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.GRANT_TYPE;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_CODE;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_PASSWORD;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockDetailsNotOAuth2ClientDetailsPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockNotClientCredentialsTokenPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockRevokeService;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockTokenGrantService;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockTokenRequestMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("토큰 엔드포인트 테스트")
class OAuth2TokenEndpointTest {

    @Nested
    @DisplayName("새 엑세스 토큰 부여")
    class GrantNewAccessToken {

        @Nested
        @DisplayName("요청한 인증타입이 null 일시")
        class WhenRequestingGrantTypeNull {
            private Principal principal;
            private Map<String, String> badRequestMap;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenDetails token = mockAccessToken().configDefault().build();

                this.principal = mockPrincipal(mockClientDetails().configDefault().build());
                this.badRequestMap = mockTokenRequestMap().configDefault().configGrantType(null).build();
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(token), mockRevokeService(token));
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.grantNewAccessToken(principal, badRequestMap))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("인증타입이 implicit 일시")
        class WhenGrantTypeImplicit {
            private Principal principal;
            private Map<String, String> badRequestMap;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenDetails token = mockAccessToken().configDefault().build();

                this.principal = mockPrincipal(mockClientDetails().configDefault().build());
                this.badRequestMap = mockTokenRequestMap().configDefault().configGrantType(AuthorizationGrantType.IMPLICIT.getValue()).build();
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(token), mockRevokeService(token));
            }

            @Test
            @DisplayName("InvalidGrantException 이 발생해야 하며 에러 코드는 UNSUPPORTED_GRANT_TYPE 이어야 한다.")
            void shouldThrowsInvalidGrantException() {
                OAuth2Error error = assertThrows(InvalidGrantException.class, () -> endpoint.grantNewAccessToken(principal, badRequestMap))
                        .getError();
                assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("인증 객체의 타입이 ClientCredentialsToken 이 아닐시")
        class WhenAuthenticationTypeNotClientCredentialsToken {
            private Principal principal;
            private Map<String, String> requestMap;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenDetails token = mockAccessToken().configDefault().build();

                this.principal = mockNotClientCredentialsTokenPrincipal();
                this.requestMap = mockTokenRequestMap().configDefault().build();
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(token), mockRevokeService(token));
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(principal, requestMap));
            }
        }

        @Nested
        @DisplayName("인증 객체의 주체가 OAuth2ClientDetails 가 아닐시")
        class WhenPrincipalIsNotOAuth2ClientDetails {
            private Principal principal;
            private Map<String, String> requestMap;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenDetails token = mockAccessToken().configDefault().build();

                this.principal = mockDetailsNotOAuth2ClientDetailsPrincipal();
                this.requestMap = mockTokenRequestMap().configDefault().build();
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(token), mockRevokeService(token));
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(principal, requestMap));
            }
        }

        @Nested
        @DisplayName("요청이 옳바를시")
        class WhenAllowedRequesting {
            private Principal principal;
            private OAuth2ClientDetails clientDetails;
            private Map<String, String> requestMap;
            private OAuth2AccessTokenGranter grantService;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2AccessTokenDetails token = mockAccessToken().configDefault().build();

                this.clientDetails = mockClientDetails().configDefault().build();
                this.principal = mockPrincipal(clientDetails);
                this.requestMap = mockTokenRequestMap().configDefault().build();
                this.grantService = mockTokenGrantService(token);
                this.endpoint = new OAuth2TokenEndpoint(grantService, mockRevokeService(token));
            }

            @Test
            @DisplayName("클라이언트 인증 정보와 전달 받은 매개 변수로 엑세스 토큰을 생성해야 한다.")
            void shouldCreateAccessTokenViaRequestingGrantType() {
                ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

                endpoint.grantNewAccessToken(principal, requestMap);
                verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
                assertEquals(new AuthorizationGrantType(GRANT_TYPE), requestCaptor.getValue().getGrantType());
                assertEquals(RAW_USERNAME, requestCaptor.getValue().getUsername());
                assertEquals(RAW_PASSWORD, requestCaptor.getValue().getPassword());
                assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
                assertEquals(RAW_CODE, requestCaptor.getValue().getCode());
                assertEquals(REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
                assertEquals(RAW_SCOPES, requestCaptor.getValue().getScopes());
            }

            @Test
            @DisplayName("헤더의 Pragma 옵션은 no-cache 어야 한다.")
            void shouldHeaderPragmaIsNoCache() {
                ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(principal, requestMap);

                assertEquals("no-cache", result.getHeaders().getPragma());
            }

            @Test
            @DisplayName("헤더의 Content-Type 은 application/json 이어야 한다.")
            void shouldHeaderContentTypeIsApplicationJson() {
                ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(principal, requestMap);

                assertEquals(MediaType.APPLICATION_JSON, result.getHeaders().getContentType());
            }
        }
    }

    @Nested
    @DisplayName("토큰 삭제")
    class RevokeToken {

        @Nested
        @DisplayName("인증 객체의 타입이 ClientCredentialsToken 이 아닐시")
        class WhenAuthenticationTypeNotClientCredentialsToken {
            private Principal principal;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.principal = mockNotClientCredentialsTokenPrincipal();
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(null), mockRevokeService(null));
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.revokeAccessToken(principal, ""));
            }
        }

        @Nested
        @DisplayName("요청 받은 Token 이 null 일시")
        class WhenRequestingTokenIsNull {
            private Principal principal;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.principal = mockPrincipal(mockClientDetails().configDefault().build());
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(null), mockRevokeService(null));
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.revokeAccessToken(principal, null))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("요청이 옳바를시")
        class WhenAllowedRequesting {
            private Principal principal;
            private OAuth2TokenRevoker revokeService;
            private OAuth2TokenEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2ClientDetails clientDetails = mockClientDetails().configDefault().build();
                OAuth2AccessTokenDetails accessTokenDetails = mockAccessToken().configDefault().build();

                this.principal = mockPrincipal(clientDetails);
                this.revokeService = mockRevokeService(accessTokenDetails);
                this.endpoint = new OAuth2TokenEndpoint(mockTokenGrantService(accessTokenDetails), revokeService);
            }

            @Test
            @DisplayName("요청 받은 토큰을 삭제해야 한다.")
            void shouldRemoveRequestingToken() {
                endpoint.revokeAccessToken(principal, RAW_TOKEN_ID);
                verify(revokeService, times(1)).revoke(RAW_TOKEN_ID);
            }
        }
    }
}