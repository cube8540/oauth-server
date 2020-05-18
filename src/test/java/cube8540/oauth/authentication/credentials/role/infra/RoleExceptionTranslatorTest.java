package cube8540.oauth.authentication.credentials.role.infra;

import cube8540.oauth.authentication.credentials.role.domain.exception.RoleInvalidException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleNotFoundException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleRegisterException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("권한 에러 변환기 테스트")
class RoleExceptionTranslatorTest {

    private RoleExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new RoleExceptionTranslator();
    }

    @Nested
    @DisplayName("RoleInvalidException 변환")
    class TranslateRoleInvalidException {
        private RoleInvalidException exception;

        @BeforeEach
        void setup() {
            this.exception = mock(RoleInvalidException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("RoleNotFoundException 변환")
    class TranslateRoleNotFoundException {
        private RoleNotFoundException e;

        @BeforeEach
        void setup() {
            this.e = mock(RoleNotFoundException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 404 이어야 한다.")
        void shouldHttpStatusCodeIs404() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }

    }

    @Nested
    @DisplayName("RoleRegisterException 변환")
    class TranslateRoleRegisterException {
        private RoleRegisterException e;

        @BeforeEach
        void setup() {
            this.e = mock(RoleRegisterException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }

    }

}