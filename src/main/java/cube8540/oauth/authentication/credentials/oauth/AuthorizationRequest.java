package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;

import java.net.URI;
import java.util.Set;

public interface AuthorizationRequest {

    String getClientId();

    String getUsername();

    String getState();

    URI getRedirectUri();

    Set<String> getRequestScopes();

    OAuth2AuthorizationResponseType getResponseType();

    void setRedirectUri(URI redirectUri);

    void setRequestScopes(Set<String> requestScopes);

}
