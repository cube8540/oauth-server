package cube8540.oauth.authentication.credentials.oauth.security;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;

import java.net.URI;
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode
public class DefaultAuthorizationRequest implements AuthorizationRequest {

    private String clientId;

    private String state;

    private String username;

    @Setter
    private URI redirectUri;

    @Setter
    private Set<String> requestScopes;

    private OAuth2AuthorizationResponseType responseType;

    public DefaultAuthorizationRequest(Map<String, String> requestMap, Principal principal) {
        this.clientId = requestMap.get(OAuth2Utils.AuthorizationRequestKey.CLIENT_ID);
        this.state = requestMap.get(OAuth2Utils.AuthorizationRequestKey.STATE);
        this.requestScopes = OAuth2Utils.extractScopes(requestMap.get(OAuth2Utils.AuthorizationRequestKey.SCOPE));
        this.username = Optional.ofNullable(principal).map(Principal::getName).orElse(null);
        this.redirectUri = Optional.ofNullable(requestMap.get(OAuth2Utils.AuthorizationRequestKey.REDIRECT_URI))
                .map(URI::create).orElse(null);
        if (OAuth2AuthorizationResponseType.CODE.getValue()
                .equals(requestMap.get(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE))) {
            this.responseType = OAuth2AuthorizationResponseType.CODE;
        } else if (OAuth2AuthorizationResponseType.TOKEN.getValue()
                .equals(requestMap.get(OAuth2Utils.AuthorizationRequestKey.RESPONSE_TYPE))) {
            this.responseType = OAuth2AuthorizationResponseType.TOKEN;
        }
    }

    public DefaultAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        this.clientId = authorizationRequest.getClientId();
        this.state = authorizationRequest.getState();
        this.username = authorizationRequest.getUsername();
        this.redirectUri = authorizationRequest.getRedirectUri();
        this.responseType = authorizationRequest.getResponseType();
        if (authorizationRequest.getRequestScopes() != null) {
            this.requestScopes = new HashSet<>(authorizationRequest.getRequestScopes());
        }
    }
}
