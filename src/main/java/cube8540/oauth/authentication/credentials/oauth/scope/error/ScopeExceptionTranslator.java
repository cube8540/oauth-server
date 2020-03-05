package cube8540.oauth.authentication.credentials.oauth.scope.error;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class ScopeExceptionTranslator implements ExceptionTranslator<ErrorMessage<?>> {

    @Override
    public ResponseEntity<ErrorMessage<?>> translate(Exception exception) {
        if (exception instanceof ScopeInvalidException) {
            ScopeInvalidException e = ((ScopeInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors()));
        } else if (exception instanceof ScopeRegisterException) {
            ScopeRegisterException e = ((ScopeRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof ScopeNotFoundException) {
            ScopeNotFoundException e = ((ScopeNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            if (log.isErrorEnabled()) {
                log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            }
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
