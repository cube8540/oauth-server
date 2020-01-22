package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequestValidator;

public class DefaultOAuth2TokenRequestValidator implements OAuth2TokenRequestValidator {
    @Override
    public boolean validateScopes(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return tokenRequest.scopes() == null || clientDetails.scope().containsAll(tokenRequest.scopes());
    }
}
