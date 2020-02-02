package cube8540.oauth.authentication.credentials.oauth;

import lombok.EqualsAndHashCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;

import java.net.URI;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@EqualsAndHashCode
public class DefaultAuthorizationRequest implements AuthorizationRequest {

    private String clientId;

    private String state;

    private String username;

    private URI redirectURI;

    private Set<String> scopes;

    private OAuth2AuthorizationResponseType responseType;

    public DefaultAuthorizationRequest(Map<String, String> requestMap, Principal principal) {
        this.clientId = requestMap.get(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID);
        this.state = requestMap.get(OAuth2Utils.AuthorizationRequestKey.STATE);
        this.username = principal.getName();
        this.scopes = OAuth2Utils.extractScopes(requestMap.get(OAuth2Utils.AuthorizationRequestKey.SCOPE));
        if (requestMap.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI) != null) {
            this.redirectURI = URI.create(requestMap.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI));
        }
        if (OAuth2AuthorizationResponseType.CODE.getValue()
                .equals(requestMap.get(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE))) {
            this.responseType = OAuth2AuthorizationResponseType.CODE;
        } else if (OAuth2AuthorizationResponseType.TOKEN.getValue()
                .equals(requestMap.get(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE))) {
            this.responseType = OAuth2AuthorizationResponseType.TOKEN;
        }
    }

    public DefaultAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        this.clientId = authorizationRequest.clientId();
        this.state = authorizationRequest.state();
        this.username = authorizationRequest.username();
        this.redirectURI = authorizationRequest.redirectURI();
        this.responseType = authorizationRequest.responseType();
        if (authorizationRequest.requestScopes() != null) {
            this.scopes = new HashSet<>(authorizationRequest.requestScopes());
        }
    }

    @Override
    public String clientId() {
        return clientId;
    }

    @Override
    public String username() {
        return username;
    }

    @Override
    public String state() {
        return state;
    }

    @Override
    public URI redirectURI() {
        return redirectURI;
    }

    @Override
    public Set<String> requestScopes() {
        return scopes;
    }

    @Override
    public OAuth2AuthorizationResponseType responseType() {
        return responseType;
    }

    @Override
    public void setRedirectURI(URI redirectURI) {
        this.redirectURI = redirectURI;
    }

    @Override
    public void setRequestScopes(Set<String> requestScope) {
        this.scopes = Collections.unmodifiableSet(requestScope);
    }
}
