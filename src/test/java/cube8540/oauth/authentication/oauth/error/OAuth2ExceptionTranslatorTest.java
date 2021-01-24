package cube8540.oauth.authentication.oauth.error;

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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

    @Test
    @DisplayName("OAuth2 클라이언트 인증 관련 예외 변환")
    void translateOAuth2ClientAuthenticationException() {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT);
        AbstractOAuth2AuthenticationException exception = mock(AbstractOAuth2AuthenticationException.class);

        when(exception.getStatusCode()).thenReturn(401);
        when(exception.getError()).thenReturn(error);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertEquals(error, result.getBody());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }

    @Test
    @DisplayName("OAuth2 지원 되지 인증 방식 관련 예외 변환")
    void translateOAuth2NotSupportedAuthenticationMethodException() {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE);
        AbstractOAuth2AuthenticationException exception = mock(AbstractOAuth2AuthenticationException.class);

        when(exception.getStatusCode()).thenReturn(400);
        when(exception.getError()).thenReturn(error);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(error, result.getBody());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }

    @Test
    @DisplayName("지원 되지 않는 메소드 타입에 관한 예외 변환")
    void translateNotSupportedMethodException() {
        HttpRequestMethodNotSupportedException exception = mock(HttpRequestMethodNotSupportedException.class);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.METHOD_NOT_ALLOWED, result.getStatusCode());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }

    @Test
    @DisplayName("클라이언트 등록 관련 예외 변환")
    void translateClientRegistrationException() {
        OAuth2ClientRegistrationException exception = mock(OAuth2ClientRegistrationException.class);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }

    @Test
    @DisplayName("엑세스 토큰을 찾을 수 없는 예외 변환")
    void translateOAuth2AccessTokenNotFoundException() {
        OAuth2AccessTokenNotFoundException exception = mock(OAuth2AccessTokenNotFoundException.class);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }

    @Test
    @DisplayName("정의 되지 않은 예외 변환")
    void translateNotDefinedException() {
        Exception exception = mock(Exception.class);

        ResponseEntity<OAuth2Error> result = translator.translate(exception);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertEquals(CacheControl.noStore().getHeaderValue(), result.getHeaders().getCacheControl());
        assertEquals("no-cache", result.getHeaders().getPragma());
    }
}
