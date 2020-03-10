package cube8540.oauth.authentication.credentials.oauth;

import java.util.Set;

public class DefaultOAuth2RequestValidator implements OAuth2RequestValidator {
    @Override
    public boolean validateScopes(OAuth2ClientDetails clientDetails, Set<String> scopes) {
        return validateScopes(clientDetails.getScopes(), scopes);
    }

    @Override
    public boolean validateScopes(Set<String> approvalScopes, Set<String> requestScopes) {
        return requestScopes == null || approvalScopes.containsAll(requestScopes);
    }
}
