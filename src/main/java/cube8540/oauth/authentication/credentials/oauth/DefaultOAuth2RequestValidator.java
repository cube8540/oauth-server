package cube8540.oauth.authentication.credentials.oauth;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;

import java.util.Set;

public class DefaultOAuth2RequestValidator implements OAuth2RequestValidator {
    @Override
    public boolean validateScopes(OAuth2ClientDetails clientDetails, Set<String> scopes) {
        return scopes == null || clientDetails.scope().containsAll(scopes);
    }
}
