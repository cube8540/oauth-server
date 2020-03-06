package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.RAW_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockAccessTokenReadService;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockDetailsNotOAuth2ClientDetailsPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockIntrospectionConverter;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockNotClientCredentialsTokenPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.token.endpoint.TokenEndpointTestHelper.mockPrincipal;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("토큰 정보 확인 엔드포인트 테스트")
class OAuth2TokenIntrospectionEndpointTest {

    @Nested
    @DisplayName("토큰 정보 검색")
    class Introspection {

        @Nested
        @DisplayName("요청 정보에서 Token 이 없을시")
        class WhenRequestingTokenNull {
            private Principal principal;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.principal = mockPrincipal(null);
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().build());
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.introspection(principal, null))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }

        @Nested
        @DisplayName("인증 객체의 타입이 ClientCredentialsToken 이 아닐시")
        class WhenAuthenticationTypeNotClientCredentialsToken {
            private Principal principal;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.principal = mockNotClientCredentialsTokenPrincipal();
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(principal, RAW_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("인증 객체의 주체가 OAuth2ClientDetails 가 아닐시")
        class WhenPrincipalIsNotOAuth2ClientDetails {
            private Principal clientCredentialsToken;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.clientCredentialsToken = mockDetailsNotOAuth2ClientDetailsPrincipal();
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(this.clientCredentialsToken, RAW_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("옳바른 요청일시")
        class WhenAllowedRequesting {
            private Principal principal;
            private Map<String, Object> map;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                OAuth2ClientDetails client = mockClientDetails().configDefault().build();
                OAuth2AccessTokenDetails accessToken = mockAccessToken().configDefault().build();

                this.principal = mockPrincipal(client);
                this.map = new HashMap<>();
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().registerToken(accessToken).build());
                this.endpoint.setConverter(mockIntrospectionConverter().configConverting(accessToken, map).build());
            }

            @Test
            @DisplayName("서비스에서 반환된 엑세스 토큰을 컨버팅 하여 반환해야 한다.")
            void shouldReturnsConvertedAccessTokenReturnedFromService() {
                Map<String, Object> response = endpoint.introspection(principal, RAW_TOKEN_ID);

                assertEquals(map, response);
            }
        }
    }

    @Nested
    @DisplayName("토큰 유저 정보")
    class ReadUserInfo {

        @Nested
        @DisplayName("인증 객체의 타입이 ClientCredentialsToken 이 아닐시")
        class WhenAuthenticationTypeNotClientCredentialsToken {
            private Principal token;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.token = mockNotClientCredentialsTokenPrincipal();
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().build());
            }

            @Test
            @DisplayName("InsufficientAuthenticationException 이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.userInfo(token, RAW_TOKEN_ID));
            }
        }

        @Nested
        @DisplayName("요청 받은 Token 이 null 일시")
        class WhenRequestingTokenIsNull {
            private Principal token;
            private OAuth2TokenIntrospectionEndpoint endpoint;

            @BeforeEach
            void setup() {
                this.token = mockPrincipal(mockClientDetails().configDefault().build());
                this.endpoint = new OAuth2TokenIntrospectionEndpoint(mockAccessTokenReadService().build());
            }

            @Test
            @DisplayName("InvalidRequestException 이 발생해야 하며 에러 코드는 INVALID_REQUEST 이어야 한다.")
            void shouldThrowsInvalidRequestException() {
                OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.userInfo(token, null))
                        .getError();
                assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
            }
        }
    }
}