package cube8540.oauth.authentication.credentials.oauth;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;

import java.util.Set;

public interface OAuth2RequestValidator {

    boolean validateScopes(OAuth2ClientDetails clientDetails, Set<String> scopes);

    boolean validateScopes(Set<String> approvalScopes, Set<String> requestScopes);

}
