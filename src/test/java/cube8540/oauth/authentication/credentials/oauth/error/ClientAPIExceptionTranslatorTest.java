package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientInvalidException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientRegisterException;
import cube8540.oauth.authentication.credentials.oauth.client.infra.ClientAPIExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.Serializable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("클라이언트 에러 변환 클래스 테스트")
class ClientAPIExceptionTranslatorTest {

    private ClientAPIExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new ClientAPIExceptionTranslator();
    }

    @Nested
    @DisplayName("ClientAuthorizationException 변환")
    class TranslateClientAuthorizationException {
        private ClientAuthorizationException e;

        @BeforeEach
        void setup() {
            this.e = mock(ClientAuthorizationException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 401 이어야 한다.")
        void shouldHttpStatusCodeIs401() {
            ResponseEntity<ErrorMessage<? extends Serializable>> response = translator.translate(e);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("ClientInvalidException 변환")
    class TranslateClientInvalidException {
        private ClientInvalidException e;

        @BeforeEach
        void setup() {
            this.e = mock(ClientInvalidException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<? extends Serializable>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("ClientNotFoundException 변환")
    class TranslateClientNotFoundException {
        private ClientNotFoundException e;

        @BeforeEach
        void setup() {
            this.e = mock(ClientNotFoundException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 404 이어야 한다.")
        void shouldHttpStatusCodeIs404() {
            ResponseEntity<ErrorMessage<? extends Serializable>> response = translator.translate(e);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("ClientRegisterException 변환")
    class TranslateClientRegisterException {
        private ClientRegisterException e;

        @BeforeEach
        void setup() {
            this.e = mock(ClientRegisterException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<? extends Serializable>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

}