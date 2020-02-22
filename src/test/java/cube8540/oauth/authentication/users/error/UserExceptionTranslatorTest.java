package cube8540.oauth.authentication.users.error;

import cube8540.oauth.authentication.error.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

@DisplayName("유저 에러 변환기 테스트")
class UserExceptionTranslatorTest {

    private UserExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new UserExceptionTranslator();
    }

    @Nested
    @DisplayName("UserNotFoundException 변환")
    class TranslateUserNotFoundException {

        private UserNotFoundException e;

        @BeforeEach
        void setup() {
            this.e = mock(UserNotFoundException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 404 이어야 한다.")
        void shouldHttpStatsCodeIs404() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("UserRegisterException 변환")
    class TranslateUserRegisterException {

        private UserRegisterException e;

        @BeforeEach
        void setup() {
            this.e = mock(UserRegisterException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatsCodeIs400() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("UserInvalidException 변환")
    class TranslateUserInvalidException {

        private UserInvalidException e;

        @BeforeEach
        void setup() {
            this.e = mock(UserInvalidException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 400 이어야 한다.")
        void shouldHttpStatsCodeIs400() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }
    }

    @Nested
    @DisplayName("UserAuthorizationException 변환")
    class TranslateUserAuthorizationException {

        private UserAuthorizationException e;

        @BeforeEach
        void setup() {
            this.e = mock(UserAuthorizationException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 401 이어야 한다.")
        void shouldHttpStatsCodeIs401() {
            ResponseEntity<ErrorMessage<?>> response = translator.translate(e);
            assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        }
    }

}