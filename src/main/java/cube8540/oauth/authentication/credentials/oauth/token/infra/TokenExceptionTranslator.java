package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.exception.TokenAccessDeniedException;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class TokenExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {
    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof TokenAccessDeniedException) {
            TokenAccessDeniedException e = ((TokenAccessDeniedException) exception);
            return new ResponseEntity<>(ErrorMessage.instance(e.getCode(), e.getDescription()), HttpStatus.FORBIDDEN);
        } else {
            log.error("Handle exception {} {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR);
        }
    }
}