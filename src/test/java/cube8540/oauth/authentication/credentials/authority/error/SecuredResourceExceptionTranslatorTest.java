package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceInvalidException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.ResourceRegisterException;
import cube8540.oauth.authentication.credentials.authority.infra.SecuredResourceExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("자원 예외 변환기 클래스 테스트")
class SecuredResourceExceptionTranslatorTest {
    private static final String DESCRIPTION = "DESCRIPTION";

    private SecuredResourceExceptionTranslator translator;

    @BeforeEach
    void setup() {
        this.translator = new SecuredResourceExceptionTranslator();
    }

    @Nested
    @DisplayName("ResourceNotFoundException 변환")
    class TranslateResourceNotFoundException {
        private ResourceNotFoundException exception;

        @BeforeEach
        void setup() {
            this.exception = ResourceNotFoundException.instance(DESCRIPTION);
        }

        @Test
        @DisplayName("상태 코드는 404 이어야 한다.")
        void shouldHttpStatusCodeIs404() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        }

        @Test
        @DisplayName("에러 코드는 NOT_FOUND 이어야 한다.")
        void shouldErrorCodeIsNotFound() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(ErrorCodes.NOT_FOUND, response.getBody().getErrorCode());
        }

        @Test
        @DisplayName("에러에 대한 정보가 포함되어야 한다.")
        void shouldIncludeErrorDescription() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(DESCRIPTION, response.getBody().getDescription());
        }
    }

    @Nested
    @DisplayName("ResourceRegisterException 변환")
    class TranslateResourceRegisterException {
        private ResourceRegisterException exception;

        @BeforeEach
        void setup() {
            this.exception = ResourceRegisterException.existsIdentifier(DESCRIPTION);
        }

        @Test
        @DisplayName("상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }

        @Test
        @DisplayName("에러 코드는 예외에 저장되어 있는 에러 코드 이어야 한다.")
        void shouldErrorCodeIsNotFound() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(exception.getCode(), response.getBody().getErrorCode());
        }

        @Test
        @DisplayName("에러에 대한 정보가 포함되어야 한다.")
        void shouldIncludeErrorDescription() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(exception.getDescription(), response.getBody().getDescription());
        }
    }

    @Nested
    @DisplayName("ResourceInvalidException 변환")
    class TranslateResourceInvalidException {
        private ResourceInvalidException exception;
        private List<ValidationError> errors;

        @BeforeEach
        void setup() {
            this.errors = Arrays.asList(new ValidationError("p", "v"), new ValidationError("p", "v1"), new ValidationError("p", "v2"));
            this.exception = ResourceInvalidException.instance(errors);
        }

        @Test
        @DisplayName("상태 코드는 400 이어야 한다.")
        void shouldHttpStatusCodeIs400() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        }

        @Test
        @DisplayName("에러 코드는 예외에 저장되어 있는 에러 코드 이어야 한다.")
        void shouldErrorCodeIsNotFound() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(exception.getCode(), response.getBody().getErrorCode());
        }

        @Test
        @DisplayName("잘못된 속성에 대한 정보가 포함되어야 한다.")
        void shouldIncludeInvalidPropertyInfo() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            Assertions.assertArrayEquals(errors.toArray(), (Object[]) response.getBody().getDescription());
        }
    }

    @Nested
    @DisplayName("기타 예외 상황일시")
    class TranslateException {
        private Exception exception;

        @BeforeEach
        void setup() {
            this.exception = new Exception();
        }

        @Test
        @DisplayName("HTTP 상태 코드는 500 이어야 한다.")
        void shouldHttpStatusCodeIs500() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        }

        @Test
        @DisplayName("에러 코드는 SERVER_ERROR 이어야 한다.")
        void shouldErrorCodeIsServerError() {
            ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);

            assertNotNull(response.getBody());
            assertEquals(ErrorCodes.SERVER_ERROR, response.getBody().getErrorCode());
        }
    }
}