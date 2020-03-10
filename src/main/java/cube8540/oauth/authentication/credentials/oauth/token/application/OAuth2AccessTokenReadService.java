package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import org.springframework.security.core.userdetails.UserDetails;

public interface OAuth2AccessTokenReadService {

    OAuth2AccessTokenDetails readAccessToken(String tokenValue);

    UserDetails readAccessTokenUser(String tokenValue);

}
