package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 기본 에러 변환기 테스트")
class OAuth2ExceptionTranslatorTest {

    private OAuth2ExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new OAuth2ExceptionTranslator();
    }

    @Nested
    @DisplayName("발생한 에러가 AbstractOAuth2AuthenticationException에 관련되었을시")
    class WhenExceptionIsAbstractOAuth2AuthenticationException {
        private AbstractOAuth2AuthenticationException exception0;
        private AbstractOAuth2AuthenticationException exception1;
        private OAuth2Error error0;
        private OAuth2Error error1;

        @BeforeEach
        void setup() {
            this.exception0 = mock(AbstractOAuth2AuthenticationException.class);
            this.exception1 = mock(AbstractOAuth2AuthenticationException.class);
            this.error0 = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);
            this.error1 = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);

            when(exception0.getStatusCode()).thenReturn(401);
            when(exception0.getError()).thenReturn(error0);
            when(exception1.getStatusCode()).thenReturn(400);
            when(exception1.getError()).thenReturn(error1);
        }

        @Test
        @DisplayName("ResponseEntity의 HTTP 상태값은 OAuth2Error에서 반환된 HTTP 상태값과 같아야 한다.")
        void shouldSameHttpStatusCode() {
            ResponseEntity<OAuth2Error> result0 = translator.translate(exception0);
            ResponseEntity<OAuth2Error> result1 = translator.translate(exception1);

            assertEquals(HttpStatus.UNAUTHORIZED, result0.getStatusCode());
            assertEquals(HttpStatus.BAD_REQUEST, result1.getStatusCode());
        }

        @Test
        @DisplayName("ResponseEntity의 Body값은 예외 객체에서 반환된 OAuth2Error과 같아야 한다.")
        void shouldHttpBodySameOAuth2ErrorForException() {
            ResponseEntity<OAuth2Error> result0 = translator.translate(exception0);
            ResponseEntity<OAuth2Error> result1 = translator.translate(exception1);

            assertEquals(error0, result0.getBody());
            assertEquals(error1, result1.getBody());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Cache-Control이 no-store로 저장되어야 한다.")
        void shouldHttpResponseCacheControlSetNoStore() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception0);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Pragma는 no-cache로 저장되어야 한다.")
        void shouldHttpResponsePragmaSetNoCache() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception0);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }
    }

    @Nested
    @DisplayName("지원되지 않는 메소드 타입에 관한 예외일시")
    class WhenNotSupportedMethodException {
        private HttpRequestMethodNotSupportedException exception;

        @BeforeEach
        void setup() {
            this.exception = mock(HttpRequestMethodNotSupportedException.class);
        }

        @Test
        @DisplayName("ResponseEntity의 HTTP 상태값은 405이어야 한다.")
        void shouldHttpStatusIs405() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(HttpStatus.METHOD_NOT_ALLOWED, result.getStatusCode());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Cache-Control이 no-store로 저장되어야 한다.")
        void shouldHttpResponseCacheControlSetNoStore() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Pragma는 no-cache로 저장되어야 한다.")
        void shouldHttpResponsePragmaSetNoCache() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }
    }

    @Nested
    @DisplayName("클라이언트 등록 관련 예외일시")
    class WhenClientRegistrationException {
        private ClientNotFoundException clientRegistrationException;

        @BeforeEach
        void setup() {
            this.clientRegistrationException = mock(ClientNotFoundException.class);
        }

        @Test
        @DisplayName("HTTP의 상태 코드는 401이어야 한다.")
        void shouldHttpStatusCodeIs401() {
            ResponseEntity<OAuth2Error> result = translator.translate(clientRegistrationException);

            assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Cache-Control이 no-store로 저장되어야 한다.")
        void shouldHttpResponseCacheControlSetNoStore() {
            ResponseEntity<OAuth2Error> result = translator.translate(clientRegistrationException);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Pragma는 no-cache로 저장되어야 한다.")
        void shouldHttpResponsePragmaSetNoCache() {
            ResponseEntity<OAuth2Error> result = translator.translate(clientRegistrationException);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }
    }

    @Nested
    @DisplayName("OAuth2AccessTokenNotFoundException 에러 일시")
    class WhenOAuth2AccessTokenNotFoundException {
        private OAuth2AccessTokenNotFoundException exception;

        @BeforeEach
        void setup() {
            this.exception = new OAuth2AccessTokenNotFoundException("TEST");
        }

        @Test
        @DisplayName("HTTP의 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs401() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Cache-Control이 no-store로 저장되어야 한다.")
        void shouldHttpResponseCacheControlSetNoStore() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Pragma는 no-cache로 저장되어야 한다.")
        void shouldHttpResponsePragmaSetNoCache() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }
    }

    @Nested
    @DisplayName("다른 예외가 정의된 예외가 아닐시")
    class WhenOtherwiseException {
        private Exception exception;

        @BeforeEach
        void setup() {
            this.exception = mock(Exception.class);
        }

        @Test
        @DisplayName("ResponseEntity의 HTTP 상태값은 500이어야 한다.")
        void shouldHttpStatusIs500() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Cache-Control이 no-store로 저장되어야 한다.")
        void shouldHttpResponseCacheControlSetNoStore() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        }

        @Test
        @DisplayName("ResponseEntity의 헤더에 Pragma는 no-cache로 저장되어야 한다.")
        void shouldHttpResponsePragmaSetNoCache() {
            ResponseEntity<OAuth2Error> result = translator.translate(exception);

            assertEquals("no-cache", result.getHeaders().getPragma());
        }
    }
}
