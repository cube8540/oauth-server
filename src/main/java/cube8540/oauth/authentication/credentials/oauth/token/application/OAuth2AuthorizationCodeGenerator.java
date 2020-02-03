package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;

public interface OAuth2AuthorizationCodeGenerator {

    AuthorizationCode generateNewAuthorizationCode(AuthorizationRequest request);

}
