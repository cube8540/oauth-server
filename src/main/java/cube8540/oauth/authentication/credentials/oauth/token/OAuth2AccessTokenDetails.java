package cube8540.oauth.authentication.credentials.oauth.token;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.endpoint.OAuth2AccessTokenDetailsSerializer;

import java.util.Map;
import java.util.Set;

@JsonSerialize(using = OAuth2AccessTokenDetailsSerializer.class)
public interface OAuth2AccessTokenDetails extends OAuth2TokenDetails {

    OAuth2ClientId clientId();

    Set<OAuth2ScopeId> scope();

    String tokenType();

    String username();

    OAuth2RefreshTokenDetails refreshToken();

    Map<String, String> additionalInformation();

}
