package cube8540.oauth.authentication.credentials.oauth;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;

import java.util.Set;

public interface OAuth2TokenRequestValidator {

    boolean validateScopes(OAuth2ClientDetails clientDetails, Set<String> scopes);

}
