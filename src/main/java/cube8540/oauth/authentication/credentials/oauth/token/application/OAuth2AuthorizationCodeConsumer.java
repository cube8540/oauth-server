package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;

import java.util.Optional;

public interface OAuth2AuthorizationCodeConsumer {

    Optional<OAuth2AuthorizationCode> consume(AuthorizationCode code);

}
