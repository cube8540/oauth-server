package cube8540.oauth.authentication.error;

import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.ServletWebRequest;

public interface ExceptionResponseRenderer<T> {

    void rendering(ResponseEntity<T> responseEntity, ServletWebRequest webRequest) throws Exception;

}
