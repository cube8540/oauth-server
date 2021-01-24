package cube8540.oauth.authentication.oauth.error;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("OAuth2 인증 예외 추상 클래스 테스트")
class AbstractOAuth2AuthenticationExceptionTest {

    private static final String ERROR = OAuth2ErrorCodes.INVALID_CLIENT;
    private static final String ERROR_MESSAGE = "bad client credentials";

    @Test
    @DisplayName("에러 메시지가 없을떄, toString 메소드는 error_description 속성은 제외 된다")
    void whenErrorMessageIsNullToStringMethodExcludeErrorDescription() {
        OAuth2Error error = new OAuth2Error(ERROR);
        AbstractOAuth2AuthenticationException exception = new AbstractOAuth2AuthenticationException(401, error) {};

        String result = exception.toString();
        assertEquals("error=\"invalid_client\"", result);
    }

    @Test
    @DisplayName("toString 메소드는 erro와 error_description 속성이 모두 포함 되어야 한다")
    void toStringMethodIncludeAllProperty() {
        OAuth2Error error = new OAuth2Error(ERROR, ERROR_MESSAGE, null);
        AbstractOAuth2AuthenticationException exception = new AbstractOAuth2AuthenticationException(401, error) {};

        String result = exception.toString();
        assertEquals("error=\"invalid_client\", error_description=\"bad client credentials\"", result);
    }
}