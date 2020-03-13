package cube8540.oauth.authentication.credentials.authority.infra;

import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityRegisterException;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.Serializable;

@Slf4j
public class AuthorityExceptionTranslator implements ExceptionTranslator<ErrorMessage<? extends Serializable>> {

    @Override
    public ResponseEntity<ErrorMessage<? extends Serializable>> translate(Exception exception) {
        if (exception instanceof AuthorityNotFoundException) {
            AuthorityNotFoundException e = ((AuthorityNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof AuthorityRegisterException) {
            AuthorityRegisterException e = ((AuthorityRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
