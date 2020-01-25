package cube8540.oauth.authentication.credentials.oauth;

import java.net.URI;
import java.util.Set;

public interface AuthorizationRequest {

    String clientId();

    String email();

    String state();

    URI redirectURI();

    Set<String> approvedScopes();

}
