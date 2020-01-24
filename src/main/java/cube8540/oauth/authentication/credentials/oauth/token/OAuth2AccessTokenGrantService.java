package cube8540.oauth.authentication.credentials.oauth.token;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;

public interface OAuth2AccessTokenGrantService {

    OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

}
