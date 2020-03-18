package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@DisplayName("토큰 에러 변환기 테스트")
class TokenExceptionTranslatorTest {

    private TokenExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new TokenExceptionTranslator();
    }

    @Nested
    @DisplayName("AuthenticationDeniedException 변환")
    class TranslateTokenAccessDeniedException {
        private TokenAccessDeniedException exception;

        @BeforeEach
        void setup() {
            this.exception = mock(TokenAccessDeniedException.class);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 403 이어야 한다.")
        void shouldHttpStatusCodeIs403() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);
            assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        }
    }

}