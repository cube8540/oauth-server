package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRegistrationException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.security.Principal;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("토큰 정보 확인 엔드포인트 테스트")
class OAuth2TokenIntrospectionEndpointTest {

    private static final String TOKEN_VALUE = "TOKEN-VALUE";

    private static final String RAW_CLIENT_ID = "CLIENT-ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private OAuth2AccessTokenService service;
    private OAuth2AccessTokenIntrospectionConverter converter;
    private OAuth2TokenIntrospectionEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(OAuth2AccessTokenService.class);
        this.converter = mock(OAuth2AccessTokenIntrospectionConverter.class);
        this.endpoint = new OAuth2TokenIntrospectionEndpoint(service);
        this.endpoint.setConverter(converter);
    }

    @Nested
    @DisplayName("토큰 정보 검색")
    class Introspection {

        @Nested
        @DisplayName("요청 정보에서 Token이 없을시")
        class WhenRequestingTokenNull {

            private Principal principal;

            @BeforeEach
            void setup() {
                this.principal = mock(Principal.class);
            }

            @Test
            @DisplayName("InvalidRequestException이 발생해야 한다.")
            void shouldThrowsInvalidRequestException() {
                assertThrows(InvalidRequestException.class, () -> endpoint.introspection(principal, null));
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
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(token, TOKEN_VALUE));
            }
        }

        @Nested
        @DisplayName("인증 객체의 주체가 OAuth2ClientDetails가 아닐시")
        class WhenPrincipalIsNotOAuth2ClientDetails {
            private ClientCredentialsToken clientCredentialsToken;
            private Object object;

            @BeforeEach
            void setup() {
                this.clientCredentialsToken = mock(ClientCredentialsToken.class);
                this.object = new Object();

                when(this.clientCredentialsToken.getPrincipal()).thenReturn(object);
            }

            @Test
            @DisplayName("InsufficientAuthenticationException이 발생해야 한다.")
            void shouldInsufficientAuthenticationException() {
                assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(this.clientCredentialsToken, TOKEN_VALUE));
            }
        }

        @Nested
        @DisplayName("인증 객체의 클라이언트 아이디와 검색된 엑세스 토큰의 아이디가 다를시")
        class WhenAuthenticationClientIdAndAccessTokenIdAreDifferent {
            private ClientCredentialsToken clientCredentialsToken;
            private OAuth2ClientDetails clientDetails;
            private OAuth2AuthorizedAccessToken accessToken;

            @BeforeEach
            void setup() {
                this.clientCredentialsToken = mock(ClientCredentialsToken.class);
                this.clientDetails = mock(OAuth2ClientDetails.class);
                this.accessToken = mock(OAuth2AuthorizedAccessToken.class);

                when(service.readAccessToken(TOKEN_VALUE)).thenReturn(this.accessToken);
                when(this.clientCredentialsToken.getPrincipal()).thenReturn(clientDetails);
                when(this.clientDetails.clientId()).thenReturn("DIFFERENT_CLIENT_ID");
                when(this.accessToken.getClient()).thenReturn(CLIENT_ID);
            }

            @Test
            @DisplayName("InvalidClientException이 발생해야 한다.")
            void shouldThrowsInvalidClientException() {
                assertThrows(InvalidClientException.class, () -> endpoint.introspection(this.clientCredentialsToken, TOKEN_VALUE));
            }
        }

        private ClientCredentialsToken clientCredentials;
        private Map<String, Object> responseMap;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            this.clientCredentials = mock(ClientCredentialsToken.class);
            OAuth2ClientDetails clientDetails = mock(OAuth2ClientDetails.class);
            OAuth2AuthorizedAccessToken accessToken = mock(OAuth2AuthorizedAccessToken.class);
            OAuth2AccessTokenIntrospectionConverter converter = mock(OAuth2AccessTokenIntrospectionConverter.class);
            this.responseMap = mock(Map.class);

            when(this.clientCredentials.getPrincipal()).thenReturn(clientDetails);
            when(clientDetails.clientId()).thenReturn(RAW_CLIENT_ID);
            when(accessToken.getClient()).thenReturn(CLIENT_ID);
            when(service.readAccessToken(TOKEN_VALUE)).thenReturn(accessToken);
            when(converter.convertAccessToken(accessToken)).thenReturn(responseMap);

            endpoint.setConverter(converter);
        }

        @Test
        @DisplayName("서비스에서 반환된 엑세스 토큰을 컨버팅 하여 반환해야 한다.")
        void shouldReturnsConvertedAccessTokenReturnedFromService() {
            Map<String, Object> response = endpoint.introspection(clientCredentials, TOKEN_VALUE);

            assertEquals(responseMap, response);
        }
    }

    @Nested
    @DisplayName("예외 처리")
    class HandleException {

        @Nested
        @DisplayName("OAuth2AccessTokenRegistrationException 관련 에러 발생시")
        class WhenThrowsOAuth2AccessTokenRegistrationException {
            private OAuth2ExceptionTranslator exceptionTranslator;
            private OAuth2AccessTokenRegistrationException exception;
            private ResponseEntity<OAuth2Error> responseEntity;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.exceptionTranslator = mock(OAuth2ExceptionTranslator.class);
                this.exception = mock(OAuth2AccessTokenRegistrationException.class);
                this.responseEntity = mock(ResponseEntity.class);

                when(exceptionTranslator.translate(exception)).thenReturn(responseEntity);

                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Test
            @DisplayName("예외를 응답 메시지로 변환하여 반환해야 한다.")
            void shouldReturnsConvertingException() {
                ResponseEntity<OAuth2Error> response = endpoint.handleException(exception);
                assertEquals(responseEntity, response);
            }

            @AfterEach
            void after() {
                endpoint.setExceptionTranslator(null);
            }
        }

        @Nested
        @DisplayName("OAuth2AuthenticationException 관련 에러 발생시")
        class WhenThrowsOAuth2AuthenticationException {
            private OAuth2ExceptionTranslator exceptionTranslator;
            private OAuth2AuthenticationException exception;
            private ResponseEntity<OAuth2Error> responseEntity;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.exceptionTranslator = mock(OAuth2ExceptionTranslator.class);
                this.exception = mock(OAuth2AuthenticationException.class);
                this.responseEntity = mock(ResponseEntity.class);

                when(exceptionTranslator.translate(exception)).thenReturn(responseEntity);

                endpoint.setExceptionTranslator(exceptionTranslator);
            }

            @Test
            @DisplayName("예외를 응답 메시지로 변환하여 반환해야 한다.")
            void shouldReturnsConvertingException() {
                ResponseEntity<OAuth2Error> response = endpoint.handleException(exception);
                assertEquals(responseEntity, response);
            }

            @AfterEach
            void after() {
                endpoint.setExceptionTranslator(null);
            }
        }

        @Nested
        @DisplayName("예외 발생시")
        class WhenThrowsException {
            private Exception exception;

            @BeforeEach
            void setup() {
                this.exception = mock(Exception.class);
            }

            @Test
            @DisplayName("active 플레그를 가지는 Map을 반환해야 한다.")
            void shouldActiveFlag() {
                Map<String, Boolean> result = endpoint.handleServerException(exception);

                assertTrue(result.containsKey(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE));
            }

            @Test
            @DisplayName("active 플레그는 false이어야 한다.")
            void shouldActiveFlagIsFalse() {
                Map<String, Boolean> result = endpoint.handleServerException(exception);

                assertFalse(result.get(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE));
            }
        }
    }
}