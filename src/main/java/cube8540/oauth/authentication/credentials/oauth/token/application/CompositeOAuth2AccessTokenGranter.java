package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenGrantService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.HashMap;
import java.util.Map;

public class CompositeOAuth2AccessTokenGranter implements OAuth2AccessTokenGrantService {

    private Map<AuthorizationGrantType, OAuth2AccessTokenGrantService> tokenGranterMap;

    public CompositeOAuth2AccessTokenGranter() {
        this.tokenGranterMap = new HashMap<>();
    }

    public void putTokenGranterMap(AuthorizationGrantType grantType, OAuth2AccessTokenGrantService tokenGranter) {
        this.tokenGranterMap.put(grantType, tokenGranter);
    }

    @Override
    public OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (tokenGranterMap.get(tokenRequest.grantType()) == null) {
            throw new InvalidGrantException("not supported grant type");
        }

        return tokenGranterMap.get(tokenRequest.grantType()).grant(clientDetails, tokenRequest);
    }
}
