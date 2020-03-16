package cube8540.oauth.authentication.credentials.oauth.security;

public interface OAuth2AccessTokenGranter {

    OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

}
