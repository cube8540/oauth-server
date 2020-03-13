package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;

public interface OAuth2TokenRevoker {

    OAuth2AccessTokenDetails revoke(String tokenValue);

}
