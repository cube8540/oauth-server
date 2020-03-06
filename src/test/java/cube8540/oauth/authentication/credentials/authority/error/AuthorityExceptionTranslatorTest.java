package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("권한 예외 변환기 클래스 테스트")
class AuthorityExceptionTranslatorTest {

    private static final String RAW_CODE = "CODE";
    private static final String DESCRIPTION = "DESCRIPTION";

    private AuthorityExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new AuthorityExceptionTranslator();
    }

    @Nested
    @DisplayName("AuthorityNotFoundException 변환")
    class TranslateAuthorityNotFoundException {
        private AuthorityNotFoundException e;

        @BeforeEach
        void setup() {
            this.e = mock(AuthorityNotFoundException.class);

            when(e.getCode()).thenReturn(RAW_CODE);
            when(e.getDescription()).thenReturn(DESCRIPTION);
        }

        @Test
        @DisplayName("상태 코드는 404 이어야 한다.")
        void shouldHttpStatusCodeIs404() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("AuthorityRegisterException 변환")
    class TranslateAuthorityRegisterException {

        private AuthorityRegisterException e;

        @BeforeEach
        void setup() {
            this.e = mock(AuthorityRegisterException.class);
        }

        @Test
        @DisplayName("상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("기타 예외 상황일시")
    class TranslateException {
        private Exception e;

        @BeforeEach
        void setup() {
            this.e = mock(Exception.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 500 이어야 한다.")
        void shouldHttpStatusCodeIs500() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        }
    }
}