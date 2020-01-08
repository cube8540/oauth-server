package cube8540.oauth.authentication.credentials.oauth.error;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("OAuth2 인증 예외 추상 클래스 테스트")
class AbstractOAuth2AuthenticationExceptionTest {

    private static final String ERROR = OAuth2ErrorCodes.INVALID_CLIENT;
    private static final String ERROR_MESSAGE = "bad client credentials";

    @Nested
    @DisplayName("toString 테스트")
    class ToString {

        @Nested
        @DisplayName("에러 메시지가 없을시")
        class WhenErrorMessageNull {
            private OAuth2Error error;
            private AbstractOAuth2AuthenticationException exception;

            @BeforeEach
            void setup() {
                this.error = new OAuth2Error(ERROR);
                this.exception = new AbstractOAuth2AuthenticationException(401, error) {};
            }

            @Test
            @DisplayName("toString시 error_description 속성은 제외되어야 한다.")
            void shouldToStringExcludeErrorDescriptionProperty() {
                String result = exception.toString();

                assertEquals("error=\"invalid_client\"", result);
            }
        }

        @Nested
        @DisplayName("에러 메시지가 있을시")
        class WhenErrorMessageNotNull {
            private OAuth2Error error;
            private AbstractOAuth2AuthenticationException exception;

            @BeforeEach
            void setup() {
                this.error = new OAuth2Error(ERROR, ERROR_MESSAGE, null);
                this.exception = new AbstractOAuth2AuthenticationException(401, error) {};
            }

            @Test
            @DisplayName("toString시 error와 error_description 속성이 모두 포함되어야 한다.")
            void shouldToStringIncludeAllProperty() {
                String result = exception.toString();

                assertEquals("error=\"invalid_client\", error_description=\"bad client credentials\"", result);
            }
        }
    }
}