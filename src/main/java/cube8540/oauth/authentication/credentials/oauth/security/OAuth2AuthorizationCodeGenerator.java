package cube8540.oauth.authentication.credentials.oauth.security;

public interface OAuth2AuthorizationCodeGenerator {

    AuthorizationCode generateNewAuthorizationCode(AuthorizationRequest request);

}
