package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.HashMap;
import java.util.Map;

public class OAuth2AccessTokenFactory implements OAuth2TokenFactory {

    private Map<AuthorizationGrantType, OAuth2TokenFactory> tokenFactoryMap;

    public OAuth2AccessTokenFactory() {
        this.tokenFactoryMap = new HashMap<>();
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (tokenFactoryMap.get(tokenRequest.grantType()) == null) {
            throw new InvalidGrantException("not supported grant type");
        }

        return tokenFactoryMap.get(tokenRequest.grantType()).createAccessToken(clientDetails, tokenRequest);
    }

    public void putTokenFactoryMap(AuthorizationGrantType grantType, OAuth2TokenFactory tokenFactory) {
        this.tokenFactoryMap.put(grantType, tokenFactory);
    }
}
