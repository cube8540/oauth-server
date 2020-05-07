package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AuthorizationCodeGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;

public class AuthorizationCodeResponseEnhancer implements AuthorizationResponseEnhancer {

    private OAuth2AuthorizationCodeGenerator codeGenerator;
    private AuthorizationResponseEnhancer nextEnhancer;

    public AuthorizationCodeResponseEnhancer(OAuth2AuthorizationCodeGenerator codeGenerator) {
        this.codeGenerator = codeGenerator;
    }

    @Override
    public AuthorizationResponseEnhancer setNext(AuthorizationResponseEnhancer handler) {
        this.nextEnhancer = handler;
        return this.nextEnhancer;
    }

    @Override
    public ModelAndView enhance(ModelAndView modelAndView, AuthorizationRequest request) {
        if (request.getResponseType().equals(OAuth2AuthorizationResponseType.CODE)) {
            AuthorizationCode code = codeGenerator.generateNewAuthorizationCode(request);
            modelAndView.addObject(OAuth2Utils.AuthorizationResponseKey.CODE, code.getValue());

            if (request.getState() != null) {
                modelAndView.addObject(OAuth2Utils.AuthorizationResponseKey.STATE, request.getState());
            }
        }
        return nextEnhancer != null ? nextEnhancer.enhance(modelAndView, request) : modelAndView;
    }
}
