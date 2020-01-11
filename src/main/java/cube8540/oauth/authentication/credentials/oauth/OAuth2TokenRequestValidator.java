package cube8540.oauth.authentication.credentials.oauth;

public interface OAuth2TokenRequestValidator {

    boolean validateScopes(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

}
