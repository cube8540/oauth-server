package cube8540.oauth.authentication.credentials.oauth.security;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Map;
import java.util.Set;

@Getter
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

    private URI redirectUri;

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
            this.redirectUri = URI.create(requestMap.get(OAuth2Utils.TokenRequestKey.REDIRECT_URI));
        }
    }
}
