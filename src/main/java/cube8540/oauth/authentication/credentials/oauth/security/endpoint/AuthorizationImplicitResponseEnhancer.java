package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.util.Set;

public class AuthorizationImplicitResponseEnhancer implements AuthorizationResponseEnhancer {

    private OAuth2AccessTokenGranter tokenGranter;
    private OAuth2ClientDetailsService clientDetailsService;

    private AuthorizationResponseEnhancer nextEnhancer;

    public AuthorizationImplicitResponseEnhancer(OAuth2AccessTokenGranter tokenGranter, OAuth2ClientDetailsService clientDetailsService) {
        this.tokenGranter = tokenGranter;
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    public AuthorizationResponseEnhancer setNext(AuthorizationResponseEnhancer handler) {
        this.nextEnhancer = handler;
        return this.nextEnhancer;
    }

    @Override
    public ModelAndView enhance(ModelAndView modelAndView, AuthorizationRequest request) {
        if (request.getResponseType().equals(OAuth2AuthorizationResponseType.TOKEN)) {
            OAuth2ClientDetails clientDetails = clientDetailsService.loadClientDetailsByClientId(request.getClientId());
            OAuth2AccessTokenDetails token = tokenGranter.grant(clientDetails, new ImplicitTokenRequest(request));
            enhanceRedirectUrl(modelAndView, request, token);
        }

        return nextEnhancer != null ? nextEnhancer.enhance(modelAndView, request) : modelAndView;
    }

    private void enhanceRedirectUrl(ModelAndView modelAndView, AuthorizationRequest authorizationRequest, OAuth2AccessTokenDetails token) {
        RedirectView view = (RedirectView) modelAndView.getView();
        String redirectUrl = view.getUrl() + "#access_token=" + token.getTokenValue() + "&token_type=" + token.getTokenType()
                + "&expires_in=" + token.getExpiresIn() + "&scope=" + String.join(" ", token.getScopes());
        if (authorizationRequest.getState() != null) {
            redirectUrl += "&state=" + authorizationRequest.getState();
        }
        view.setUrl(redirectUrl);
    }

    private static class ImplicitTokenRequest implements OAuth2TokenRequest {

        private final AuthorizationRequest request;

        private ImplicitTokenRequest(AuthorizationRequest request) {
            this.request = request;
        }

        @Override
        public AuthorizationGrantType getGrantType() {
            return AuthorizationGrantType.IMPLICIT;
        }

        @Override
        public String getUsername() {
            return request.getUsername();
        }

        @Override
        public String getPassword() {
            return null;
        }

        @Override
        public String getClientId() {
            return request.getClientId();
        }

        @Override
        public String getRefreshToken() {
            return null;
        }

        @Override
        public String getCode() {
            return null;
        }

        @Override
        public String getState() {
            return request.getState();
        }

        @Override
        public URI getRedirectUri() {
            return request.getRedirectUri();
        }

        @Override
        public Set<String> getScopes() {
            return request.getRequestScopes();
        }
    }
}
