package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeInvalidException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeRegisterException;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class ScopeAPIExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {

    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof ScopeInvalidException) {
            ScopeInvalidException e = ((ScopeInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors().toArray()));
        } else if (exception instanceof ScopeRegisterException) {
            ScopeRegisterException e = ((ScopeRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof ScopeNotFoundException) {
            ScopeNotFoundException e = ((ScopeNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR);
        }
    }
}
