package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class SecuredResourceExceptionTranslator implements ExceptionTranslator<ErrorMessage<?>> {
    @Override
    public ResponseEntity<ErrorMessage<?>> translate(Exception exception) {
        if (exception instanceof ResourceNotFoundException) {
            ResourceNotFoundException e = ((ResourceNotFoundException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.NOT_FOUND);
        } else if (exception instanceof ResourceRegisterException) {
            ResourceRegisterException e = ((ResourceRegisterException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.BAD_REQUEST);
        } else if (exception instanceof ResourceInvalidException) {
            ResourceInvalidException e = ((ResourceInvalidException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getErrors()), HttpStatus.BAD_REQUEST);
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
