package cube8540.oauth.authentication.credentials.oauth;

import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

@ToString
@EqualsAndHashCode
public class DefaultOAuth2TokenRequest implements OAuth2TokenRequest {

    private AuthorizationGrantType grantType;

    private String username;

    private String password;

    private String clientId;

    private String refreshToken;

    private String code;

    private String state;

    private URI redirectURI;

    private Set<String> scopes;

    public DefaultOAuth2TokenRequest(Map<String, String> requestMap) {
        this.grantType = new AuthorizationGrantType(requestMap.get(OAuth2Utils.TokenRequestKey.GRANT_TYPE));
        this.username = requestMap.get(OAuth2Utils.TokenRequestKey.USERNAME);
        this.password = requestMap.get(OAuth2Utils.TokenRequestKey.PASSWORD);
        this.clientId = requestMap.get(OAuth2Utils.TokenRequestKey.CLIENT_ID);
        this.refreshToken = requestMap.get(OAuth2Utils.TokenRequestKey.REFRESH_TOKEN);
        this.code = requestMap.get(OAuth2Utils.TokenRequestKey.CODE);
        this.state = requestMap.get(OAuth2Utils.TokenRequestKey.STATE);
        this.scopes = OAuth2Utils.extractScopes(requestMap.get(OAuth2Utils.TokenRequestKey.SCOPE));

        if (requestMap.get(OAuth2Utils.TokenRequestKey.REDIRECT_URI) != null) {
            this.redirectURI = URI.create(requestMap.get(OAuth2Utils.TokenRequestKey.REDIRECT_URI));
        }
    }

    @Override
    public AuthorizationGrantType grantType() {
        return grantType;
    }

    @Override
    public String username() {
        return username;
    }

    @Override
    public String password() {
        return password;
    }

    @Override
    public String clientId() {
        return clientId;
    }

    @Override
    public String refreshToken() {
        return refreshToken;
    }

    @Override
    public String code() {
        return code;
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
    public Set<String> scopes() {
        return Collections.unmodifiableSet(scopes);
    }
}
