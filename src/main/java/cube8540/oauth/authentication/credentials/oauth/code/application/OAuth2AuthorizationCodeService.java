package cube8540.oauth.authentication.credentials.oauth.code.application;

import cube8540.oauth.authentication.credentials.oauth.token.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.domain.OAuth2AuthorizationCode;

import java.util.Optional;

public interface OAuth2AuthorizationCodeService {

    Optional<OAuth2AuthorizationCode> consume(AuthorizationCode code);

    AuthorizationCode generateNewAuthorizationCode(OAuth2ClientDetails clientDetails, AuthorizationRequest request);

}
