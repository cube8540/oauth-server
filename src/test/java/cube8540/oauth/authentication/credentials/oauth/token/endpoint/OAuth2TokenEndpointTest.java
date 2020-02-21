package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.error.AbstractOAuth2AuthenticationException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenGrantService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("토큰 엔드포인트 테스트")
class OAuth2TokenEndpointTest {

    private static final String GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE.getValue();

    private static final String USERNAME = "email@email.com";

    private static final String PASSWORD = "Password1234!@#$";

    private static final String CLIENT_ID = "CLIENT-ID";

    private static final String REFRESH_TOKEN = "REFRESH-TOKEN";

    private static final String CODE = "CODE";

    private static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    private static final Set<String> SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));

    private OAuth2AccessTokenGrantService grantService;
    private OAuth2TokenEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.grantService = mock(OAuth2AccessTokenGrantService.class);
        this.endpoint = new OAuth2TokenEndpoint(grantService);
    }

    @Nested
    @DisplayName("새 엑세스 토큰 부여")
    class GrantNewAccessToken {

        private ClientCredentialsToken clientCredentialsToken;
        private OAuth2ClientDetails clientDetails;
        private OAuth2AccessTokenDetails tokenDetails;
        private Map<String, String> requestMap;

        @BeforeEach
        void setup() {
            this.clientCredentialsToken = mock(ClientCredentialsToken.class);
            this.clientDetails = mock(OAuth2ClientDetails.class);
            this.tokenDetails = mock(OAuth2AccessTokenDetails.class);
            this.requestMap = new HashMap<>();

            this.requestMap.put(OAuth2Utils.TokenRequestKey.GRANT_TYPE, GRANT_TYPE);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.USERNAME, USERNAME);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.PASSWORD, PASSWORD);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.CLIENT_ID, CLIENT_ID);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.REFRESH_TOKEN, REFRESH_TOKEN);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.CODE, CODE);
            this.requestMap.put(OAuth2Utils.TokenRequestKey.REDIRECT_URI, REDIRECT_URI.toString());
            this.requestMap.put(OAuth2Utils.TokenRequestKey.SCOPE, String.join(" ", SCOPES));
            when(clientCredentialsToken.getPrincipal()).thenReturn(clientDetails);
            when(grantService.grant(eq(clientDetails), any(OAuth2TokenRequest.class))).thenReturn(tokenDetails);
        }

        @Nested
        @DisplayName("요청한 인증타입이 null일시")
        class WhenRequestingGrantTypeNull {

            private ClientCredentialsToken clientCredentials;
            private Map<String, String> badRequestMap;

            @BeforeEach
            void setup() {
                OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                this.clientCredentials = mock(ClientCredentialsToken.class);
                this.badRequestMap = new HashMap<>();
                this.badRequestMap.put(OAuth2Utils.TokenRequestKey.GRANT_TYPE, null);
                when(clientCredentials.getPrincipal()).thenReturn(clientDetails);
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldThrowsInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> endpoint.grantNewAccessToken(clientCredentials, badRequestMap));
            }
        }

        @Nested
        @DisplayName("인증타입이 implicit 일시")
        class WhenGrantTypeImplicit {

            private ClientCredentialsToken clientCredentials;
            private Map<String, String> badRequestMap;

            @BeforeEach
            void setup() {
                OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
                this.clientCredentials = mock(ClientCredentialsToken.class);
                this.badRequestMap = new HashMap<>();
                this.badRequestMap.put(OAuth2Utils.TokenRequestKey.GRANT_TYPE, "implicit");
                when(clientCredentials.getPrincipal()).thenReturn(clientDetails);
            }

            @Test
            @DisplayName("InvalidGrantException이 발생해야 한다.")
            void shouldThrowsInvalidGrantException() {
                assertThrows(InvalidGrantException.class, () -> endpoint.grantNewAccessToken(clientCredentials, badRequestMap));
            }
        }

        @Nested
        @DisplayName("인증 객체의 타입이 ClientCredetialsToken이 아닐시")
        class WhenAuthenticationTypeNotClientCredentialsToken {
            private UsernamePasswordAuthenticationToken token;

            @BeforeEach
            void setup() {
                this.token = mock(UsernamePasswordAuthenticationToken.class);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(token, requestMap));
            }
        }

        @Nested
        @DisplayName("인증 객체의 주체가 OAuth2ClientDetails가 아닐시")
        class WhenPrincipalIsNotOAuth2ClientDetails {
            private ClientCredentialsToken clientCredentialsToken;

            @BeforeEach
            void setup() {
                this.clientCredentialsToken = mock(ClientCredentialsToken.class);
                Object object = new Object();

                when(this.clientCredentialsToken.getPrincipal()).thenReturn(object);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(clientCredentialsToken, requestMap));
            }
        }

        @Test
        @DisplayName("클라이언트 인증정보로 엑세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaClientCredentials() {
            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), any());
        }

        @Test
        @DisplayName("매개변수로 받은 인증 타입으로 엑세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaRequestingGrantType() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(new AuthorizationGrantType(GRANT_TYPE), requestCaptor.getValue().grantType());
        }

        @Test
        @DisplayName("매개변수로 받은 유저 아이디로 엑세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaUsername() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(USERNAME, requestCaptor.getValue().username());
        }

        @Test
        @DisplayName("매개변수로 받은 유저 패스워드로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaPassword() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(PASSWORD, requestCaptor.getValue().password());
        }

        @Test
        @DisplayName("매개변수로 받은 클라이언트 아이디로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaClientId() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(CLIENT_ID, requestCaptor.getValue().clientId());
        }

        @Test
        @DisplayName("매개변수로 받은 리플레시 토큰으로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaRefreshToken() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(REFRESH_TOKEN, requestCaptor.getValue().refreshToken());
        }

        @Test
        @DisplayName("매개변수로 받은 인증 코드로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaAuthenticationCode() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(CODE, requestCaptor.getValue().code());
        }

        @Test
        @DisplayName("매개변수로 받은 리다이렉트 주소로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaRedirectURI() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(REDIRECT_URI, requestCaptor.getValue().redirectURI());
        }

        @Test
        @DisplayName("매개변수로 받은 스코프로 액세스 토큰을 생성해야 한다.")
        void shouldCreateAccessTokenViaScope() {
            ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);

            endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);
            verify(grantService, times(1)).grant(eq(clientDetails), requestCaptor.capture());
            assertEquals(SCOPES, requestCaptor.getValue().scopes());
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200이어야 한다.")
        void shouldHttpStatusCode200() {
            ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);

            assertEquals(HttpStatus.OK, result.getStatusCode());
        }

        @Test
        @DisplayName("헤더의 Cache-Control 옵션은 no-store어야 한다.")
        void shouldHeaderCacheControlIsNoStore() {
            ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("헤더의 Pragma 옵션은 no-cache어야 한다.")
        void shouldHeaderPragmaIsNoCache() {
            ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }

        @Test
        @DisplayName("헤더의 Content-Type은 application/json이어야 한다.")
        void shouldHeaderContentTypeIsApplicationJson() {
            ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);

            assertEquals(MediaType.APPLICATION_JSON, result.getHeaders().getContentType());
        }

        @Test
        @DisplayName("생성된 엑세스 토큰을 반환해야 한다.")
        void shouldReturnsCreatedAccessToken() {
            ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(clientCredentialsToken, requestMap);

            assertEquals(tokenDetails, result.getBody());
        }
    }

    @Nested
    @DisplayName("예외 처리")
    class WhenHandleException {
        private OAuth2ExceptionTranslator translator;
        private ResponseEntity<OAuth2Error> responseEntity;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            this.translator = mock(OAuth2ExceptionTranslator.class);
            this.responseEntity = mock(ResponseEntity.class);

            endpoint.setExceptionTranslator(translator);
        }

        @Nested
        @DisplayName("OAuth2AuthenticationException 관련 에러 발생시")
        class WhenThrowsOAuth2AuthenticationException {
            private AbstractOAuth2AuthenticationException exception;

            @BeforeEach
            void setup() {
                this.exception = mock(AbstractOAuth2AuthenticationException.class);

                when(translator.translate(exception)).thenReturn(responseEntity);
            }

            @Test
            @DisplayName("예외를 응답 메시지로 변환하여 반환해야 한다.")
            void shouldReturnsConvertingException() {
                ResponseEntity<OAuth2Error> response = endpoint.handleException(exception);
                assertEquals(responseEntity, response);
            }

            @AfterEach
            void after() {
                when(translator.translate(any())).thenReturn(null);
            }
        }

        @Nested
        @DisplayName("예외 발생시")
        class WhenThrowsException {
            private Exception exception;

            @BeforeEach
            void setup() {
                this.exception = mock(AbstractOAuth2AuthenticationException.class);

                when(translator.translate(exception)).thenReturn(responseEntity);
            }

            @Test
            @DisplayName("예외를 응답 메시지로 변환하여 반환해야 한다.")
            void shouldReturnsConvertingException() {
                ResponseEntity<OAuth2Error> response = endpoint.handleException(exception);
                assertEquals(responseEntity, response);
            }

            @AfterEach
            void after() {
                when(translator.translate(any())).thenReturn(null);
            }
        }
    }
}