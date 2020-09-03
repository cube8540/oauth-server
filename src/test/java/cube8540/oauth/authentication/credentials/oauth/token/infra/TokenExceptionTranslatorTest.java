package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenNotFoundException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("토큰 에러 변환기 테스트")
class TokenExceptionTranslatorTest {

    private TokenExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new TokenExceptionTranslator();
    }

    @Test
    @DisplayName("TokenNotFoundException 변환")
    void translateTokenNotFoundException() {
        TokenNotFoundException exception = mock(TokenNotFoundException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("TokenAccessDeniedException 변환")
    void translateTokenAccessDeniedException() {
        TokenAccessDeniedException exception = mock(TokenAccessDeniedException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    @DisplayName("알 수 없는 예외 변환")
    void translateUnknownException() {
        Exception exception = new Exception();

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }
}