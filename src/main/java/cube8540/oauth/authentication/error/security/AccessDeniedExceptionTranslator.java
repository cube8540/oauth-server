package cube8540.oauth.authentication.error.security;

import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class AccessDeniedExceptionTranslator implements ExceptionTranslator<ErrorMessage<Object>> {
    @Override
    public ResponseEntity<ErrorMessage<Object>> translate(Exception exception) {
        return new ResponseEntity<>(ErrorMessage.ACCESS_DENIED_ERROR, HttpStatus.FORBIDDEN);
    }
}
