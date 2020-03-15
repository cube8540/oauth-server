package cube8540.oauth.authentication.error.security;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("접근 거부 예외 변환 클래스 테스트")
class AccessDeniedExceptionTranslatorTest {

    private AccessDeniedExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new AccessDeniedExceptionTranslator();
    }

    @Test
    @DisplayName("HTTP 상태 코드는 403 이어야 한다.")
    void httpStatusCodeIs403() {
        ResponseEntity<ErrorMessage<Object>> response = translator.translate(new Exception());

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    @DisplayName("에러 코드는 ACCESS_DENIED 이어야 한다.")
    void errorCodeIsAccessDenied() {
        ResponseEntity<ErrorMessage<Object>> response = translator.translate(new Exception());

        assertNotNull(response.getBody());
        assertEquals(ErrorCodes.ACCESS_DENIED, response.getBody().getErrorCode());
    }
}