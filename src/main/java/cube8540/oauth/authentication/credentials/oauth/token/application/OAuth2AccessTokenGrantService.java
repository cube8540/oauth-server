package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;

public interface OAuth2AccessTokenGrantService {

    OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

}
