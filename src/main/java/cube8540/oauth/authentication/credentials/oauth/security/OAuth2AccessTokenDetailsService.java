package cube8540.oauth.authentication.credentials.oauth.security;

import org.springframework.security.core.userdetails.UserDetails;

public interface OAuth2AccessTokenDetailsService {

    OAuth2AccessTokenDetails readAccessToken(String tokenValue);

    UserDetails readAccessTokenUser(String tokenValue);

}
