package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;

public interface OAuth2TokenRevokeService {

    OAuth2AccessTokenDetails revoke(String tokenValue);

}
