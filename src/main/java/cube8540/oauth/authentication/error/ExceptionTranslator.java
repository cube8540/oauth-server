package cube8540.oauth.authentication.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public interface ExceptionTranslator<T> {

    default <B> ResponseEntity<B> response(HttpStatus status, B body) {
        return new ResponseEntity<>(body, status);
    }

    ResponseEntity<T> translate(Exception exception);

}
