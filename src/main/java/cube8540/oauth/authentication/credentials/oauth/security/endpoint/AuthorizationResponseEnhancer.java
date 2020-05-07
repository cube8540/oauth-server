package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import org.springframework.web.servlet.ModelAndView;

public interface AuthorizationResponseEnhancer {

    AuthorizationResponseEnhancer setNext(AuthorizationResponseEnhancer handler);

    ModelAndView enhance(ModelAndView modelAndView, AuthorizationRequest request);

}
