package cube8540.oauth.authentication.credentials.oauth.security;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;

import java.util.Set;

public interface OAuth2RequestValidator {

    boolean validateScopes(OAuth2ClientDetails clientDetails, Set<String> scopes);

    boolean validateScopes(Set<String> approvalScopes, Set<String> requestScopes);

}
