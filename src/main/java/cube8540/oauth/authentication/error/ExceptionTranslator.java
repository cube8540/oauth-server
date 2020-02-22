package cube8540.oauth.authentication.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.Serializable;

public interface ExceptionTranslator<T extends Serializable> {

    ErrorMessage<String> UNKNOWN_SERVER_ERROR = ErrorMessage.instance(ErrorCodes.SERVER_ERROR, "unknown server error");

    default <B> ResponseEntity<B> response(HttpStatus status, B body) {
        return new ResponseEntity<>(body, status);
    }

    ResponseEntity<T> translate(Exception exception);

}
