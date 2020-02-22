package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class AuthorityExceptionTranslator implements ExceptionTranslator<ErrorMessage<?>> {

    @Override
    public ResponseEntity<ErrorMessage<?>> translate(Exception exception) {
        if (exception instanceof AuthorityNotFoundException) {
            AuthorityNotFoundException e = ((AuthorityNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof AuthorityRegisterException) {
            AuthorityRegisterException e = ((AuthorityRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            if (log.isErrorEnabled()) {
                log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            }
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
