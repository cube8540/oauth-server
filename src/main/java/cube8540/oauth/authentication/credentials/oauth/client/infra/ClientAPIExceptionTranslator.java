package cube8540.oauth.authentication.credentials.oauth.client.infra;

import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientInvalidException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientRegisterException;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class ClientAPIExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {
    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        if (exception instanceof ClientNotFoundException) {
            ClientNotFoundException e = ((ClientNotFoundException) exception);
            return response(HttpStatus.NOT_FOUND, ErrorMessage.instance(e.getCode(), e.getMessage()));
        } else if (exception instanceof ClientInvalidException) {
            ClientInvalidException  e = ((ClientInvalidException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getErrors().toArray()));
        } else if (exception instanceof ClientRegisterException) {
            ClientRegisterException e = ((ClientRegisterException) exception);
            return response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(e.getCode(), e.getMessage()));
        } else if (exception instanceof ClientAuthorizationException) {
            ClientAuthorizationException e = ((ClientAuthorizationException) exception);
            return response(HttpStatus.UNAUTHORIZED, ErrorMessage.instance(e.getCode(), e.getMessage()));
        } else {
            log.error("Handle exception {}, {}", exception.getClass(), exception.getMessage());
            return response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR);
        }
    }
}
