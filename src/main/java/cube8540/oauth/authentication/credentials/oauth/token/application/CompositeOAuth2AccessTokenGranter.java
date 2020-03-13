package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.HashMap;
import java.util.Map;

public class CompositeOAuth2AccessTokenGranter implements OAuth2AccessTokenGranter {

    private Map<AuthorizationGrantType, OAuth2AccessTokenGranter> tokenGranterMap;

    public CompositeOAuth2AccessTokenGranter() {
        this.tokenGranterMap = new HashMap<>();
    }

    public void putTokenGranterMap(AuthorizationGrantType grantType, OAuth2AccessTokenGranter tokenGranter) {
        this.tokenGranterMap.put(grantType, tokenGranter);
    }

    @Override
    public OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (tokenGranterMap.get(tokenRequest.getGrantType()) == null) {
            throw InvalidGrantException.unsupportedGrantType("unsupported grant type");
        }

        return tokenGranterMap.get(tokenRequest.getGrantType()).grant(clientDetails, tokenRequest);
    }
}
