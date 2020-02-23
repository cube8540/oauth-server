package cube8540.oauth.authentication.credentials.oauth.token;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;

import java.util.Map;
import java.util.Set;

public interface OAuth2AccessTokenDetails extends OAuth2TokenDetails {

    OAuth2ClientId getClientId();

    Set<OAuth2ScopeId> getScopes();

    String getTokenType();

    String getUsername();

    OAuth2RefreshTokenDetails getRefreshToken();

    Map<String, String> getAdditionalInformation();

}
