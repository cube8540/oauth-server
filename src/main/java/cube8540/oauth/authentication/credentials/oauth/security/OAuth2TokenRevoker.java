package cube8540.oauth.authentication.credentials.oauth.security;

public interface OAuth2TokenRevoker {

    OAuth2AccessTokenDetails revoke(String tokenValue);

}
