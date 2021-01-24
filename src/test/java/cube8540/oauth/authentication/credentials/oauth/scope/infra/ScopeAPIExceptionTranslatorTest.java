package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.ScopeInvalidException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.ScopeRegisterException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("스코프 에러 변환기 테스트")
class ScopeAPIExceptionTranslatorTest {

    private ScopeAPIExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new ScopeAPIExceptionTranslator();
    }

    @Test
    @DisplayName("ScopeInvalidException 변환")
    void translateScopeInvalidException() {
        ScopeInvalidException e = mock(ScopeInvalidException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("ScopeNotFoundException 변환")
    void translateScopeNotFoundException() {
        ScopeNotFoundException e = mock(ScopeNotFoundException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("ScopeRegisterException 변환")
    void translateScopeRegisterException() {
        ScopeRegisterException e = mock(ScopeRegisterException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }
}