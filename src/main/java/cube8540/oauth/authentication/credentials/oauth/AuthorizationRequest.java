package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;

import java.net.URI;
import java.util.Set;

public interface AuthorizationRequest {

    String clientId();

    String username();

    String state();

    URI redirectURI();

    Set<String> approvedScopes();

    OAuth2AuthorizationResponseType responseType();

}
