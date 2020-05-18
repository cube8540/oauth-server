package cube8540.oauth.authentication.credentials.role.infra;

import cube8540.oauth.authentication.credentials.role.domain.exception.RoleInvalidException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleNotFoundException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleRegisterException;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class RoleExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {
    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof RoleInvalidException) {
            RoleInvalidException e = (RoleInvalidException) (exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getErrors()), HttpStatus.BAD_REQUEST);
        } else if (exception instanceof RoleNotFoundException) {
            RoleNotFoundException e = ((RoleNotFoundException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.NOT_FOUND);
        } else if (exception instanceof RoleRegisterException) {
            RoleRegisterException e = ((RoleRegisterException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.BAD_REQUEST);
        } else {
            return new ResponseEntity<>(ErrorMessage.UNKNOWN_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
