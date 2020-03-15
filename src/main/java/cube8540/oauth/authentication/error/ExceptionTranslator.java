package cube8540.oauth.authentication.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public interface ExceptionTranslator<T> {

    ErrorMessage<Object> UNKNOWN_SERVER_ERROR = ErrorMessage.instance(ErrorCodes.SERVER_ERROR, "unknown server error");

    default <B> ResponseEntity<B> response(HttpStatus status, B body) {
        return new ResponseEntity<>(body, status);
    }

    ResponseEntity<T> translate(Exception exception);

}
