package cube8540.oauth.authentication.error;

import org.springframework.http.ResponseEntity;

import java.io.Serializable;

public interface ExceptionTranslator<T extends Serializable> {

    ResponseEntity<T> translate(Exception exception);

}
