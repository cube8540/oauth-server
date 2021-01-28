package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.users.domain.UserAuthorizationException;
import cube8540.oauth.authentication.users.domain.UserInvalidException;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import cube8540.oauth.authentication.users.domain.UserRegisterException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
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

    @Test
    @DisplayName("UserNotFoundException 변환")
    void translateUserNotFoundException() {
        UserNotFoundException e = mock(UserNotFoundException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    }

    @Test
    @DisplayName("UserRegisterException 변환")
    void translateUserRegisterException() {
        UserRegisterException e = mock(UserRegisterException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("UserInvalidException")
    void translateUserInvalidException() {
        UserInvalidException e = mock(UserInvalidException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("UserAuthorizationException")
    void translateUserAuthorizationException() {
        UserAuthorizationException e = mock(UserAuthorizationException.class);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }
}