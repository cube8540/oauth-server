package cube8540.oauth.authentication.resource.infra;

import cube8540.oauth.authentication.resource.domain.ResourceInvalidException;
import cube8540.oauth.authentication.resource.domain.ResourceNotFoundException;
import cube8540.oauth.authentication.resource.domain.ResourceRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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

    @Test
    @DisplayName("ResourceNotFoundException 변환")
    void translateResourceNotFoundException() {
        ResourceNotFoundException e = ResourceNotFoundException.instance(DESCRIPTION);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertNotNull(response.getBody());
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals(ErrorCodes.NOT_FOUND, response.getBody().getErrorCode());
        assertEquals(DESCRIPTION, response.getBody().getDescription());
    }

    @Test
    @DisplayName("ResourceRegisterException 변환")
    void translateResourceRegisterException() {
        ResourceRegisterException e = ResourceRegisterException.existsIdentifier(DESCRIPTION);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertNotNull(response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCodes.EXISTS_IDENTIFIER, response.getBody().getErrorCode());
        assertEquals(DESCRIPTION, response.getBody().getDescription());
    }

    @Test
    @DisplayName("ResourceInvalidException 변환")
    @SuppressWarnings("unchecked")
    void translateResourceInvalidException() {
        List<ValidationError> errors = Arrays.asList(new ValidationError("p", "v"), new ValidationError("p", "v1"), new ValidationError("p", "v2"));
        ResourceInvalidException e = ResourceInvalidException.instance(errors);

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(e);
        assertNotNull(response.getBody());
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorCodes.INVALID_REQUEST, response.getBody().getErrorCode());
        assertArrayEquals(errors.toArray(), ((Collection<ValidationError>) Objects.requireNonNull(response.getBody().getDescription())).toArray());
    }

    @Test
    @DisplayName("기타 예외 상황 일시")
    void translateException() {
        Exception exception = new Exception();

        ResponseEntity<ErrorMessage<Object>> response = translator.translate(exception);
        assertNotNull(response.getBody());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorCodes.SERVER_ERROR, response.getBody().getErrorCode());
    }
}