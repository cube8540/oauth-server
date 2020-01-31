package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.context.request.ServletWebRequest;

public interface OAuth2ExceptionResponseRenderer {

    void rendering(ResponseEntity<OAuth2Error> responseEntity, ServletWebRequest webRequest) throws Exception;

}
