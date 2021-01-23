package cube8540.oauth.authentication.credentials.oauth.client.infra;

import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientInvalidException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientRegisterException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("클라이언트 에러 변환 클래스 테스트")
class ClientAPIExceptionTranslatorTest {

    private ClientAPIExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new ClientAPIExceptionTranslator();
    }

    @Test
    @DisplayName("ClientAuthorizationException 변환")
    void translateClientAuthorizationException() {
        ClientAuthorizationException e = mock(ClientAuthorizationException.class);

        ResponseEntity<ErrorMessage<Object>> result = translator.translate(e);
        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
    }

    @Test
    @DisplayName("ClientInvalidException 변환")
    void translateClientInvalidException() {
        ClientInvalidException e = mock(ClientInvalidException.class);

        ResponseEntity<ErrorMessage<Object>> result = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }

    @Test
    @DisplayName("ClientNotFoundException 변환")
    void translateClientNotFoundException() {
        ClientNotFoundException e = mock(ClientNotFoundException.class);

        ResponseEntity<ErrorMessage<Object>> result = translator.translate(e);
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    @DisplayName("ClientRegisterException 변환")
    void translateClientRegisterException() {
        ClientRegisterException e = mock(ClientRegisterException.class);

        ResponseEntity<ErrorMessage<Object>> result = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
    }
}