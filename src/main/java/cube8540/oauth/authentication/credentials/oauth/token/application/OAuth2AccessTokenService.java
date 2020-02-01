package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;

public interface OAuth2AccessTokenService {

    OAuth2AuthorizedAccessToken readAccessToken(String tokenValue);

}
