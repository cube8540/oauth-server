package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;

public interface OAuth2ExceptionTranslator {

    ResponseEntity<OAuth2Error> translate(Exception exception);

}
