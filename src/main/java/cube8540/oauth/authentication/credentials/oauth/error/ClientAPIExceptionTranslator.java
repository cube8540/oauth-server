package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
public class ClientAPIExceptionTranslator implements ExceptionTranslator<ErrorMessage<?>> {
    @Override
    public ResponseEntity<ErrorMessage<?>> translate(Exception exception) {
        if (exception instanceof ClientNotFoundException) {
            ClientNotFoundException e = ((ClientNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof ClientInvalidException) {
            ClientInvalidException  e = ((ClientInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors()));
        } else if (exception instanceof ClientRegisterException) {
            ClientRegisterException e = ((ClientRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else if (exception instanceof ClientAuthorizationException) {
            ClientAuthorizationException e = ((ClientAuthorizationException) exception);
            return response(HttpStatus.UNAUTHORIZED, ErrorMessage.instance(e.getCode(), e.getDescription()));
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, UNKNOWN_SERVER_ERROR);
        }
    }
}
