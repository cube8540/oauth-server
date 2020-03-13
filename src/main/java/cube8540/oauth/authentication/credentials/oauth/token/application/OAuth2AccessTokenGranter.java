package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;

public interface OAuth2AccessTokenGranter {

    OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

}
