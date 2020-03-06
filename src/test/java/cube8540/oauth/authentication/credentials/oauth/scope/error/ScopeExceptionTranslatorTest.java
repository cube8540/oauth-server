package cube8540.oauth.authentication.credentials.oauth.scope.error;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@DisplayName("스코프 에러 변환기 테스트")
class ScopeExceptionTranslatorTest {

    private ScopeExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new ScopeExceptionTranslator();
    }

    @Nested
    @DisplayName("ScopeInvalidException 변환")
    class TranslateScopeInvalidException {
        private ScopeInvalidException e;

        @BeforeEach
        void setup() {
            this.e = mock(ScopeInvalidException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("ScopeNotFoundException 변환")
    class TranslateScopeNotFoundException {
        private ScopeNotFoundException e;

        @BeforeEach
        void setup() {
            this.e = mock(ScopeNotFoundException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 404 이어야 한다.")
        void shouldHttpStatusCodeIs404() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }

    }

    @Nested
    @DisplayName("ScopeRegisterException 변환")
    class TranslateScopeRegisterException {
        private ScopeRegisterException e;

        @BeforeEach
        void setup() {
            this.e = mock(ScopeRegisterException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }

    }

}