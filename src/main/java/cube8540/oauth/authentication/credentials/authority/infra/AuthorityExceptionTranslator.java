package cube8540.oauth.authentication.credentials.authority.infra;

import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityInvalidException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityRegisterException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class AuthorityExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {

    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof AuthorityNotFoundException) {
            AuthorityNotFoundException e = ((AuthorityNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof AuthorityInvalidException) {
            AuthorityInvalidException e = ((AuthorityInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors().toArray()));
        } else if (exception instanceof AuthorityRegisterException) {
            AuthorityRegisterException e = ((AuthorityRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
