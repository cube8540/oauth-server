package cube8540.oauth.authentication.credentials.resource.infra;

import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceInvalidException;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceRegisterException;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class SecuredResourceExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {
    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof ResourceNotFoundException) {
            ResourceNotFoundException e = ((ResourceNotFoundException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.NOT_FOUND);
        } else if (exception instanceof ResourceRegisterException) {
            ResourceRegisterException e = ((ResourceRegisterException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.BAD_REQUEST);
        } else if (exception instanceof ResourceInvalidException) {
            ResourceInvalidException e = ((ResourceInvalidException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getErrors().toArray()), HttpStatus.BAD_REQUEST);
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR);
        }
    }
}
