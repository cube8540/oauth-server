package cube8540.oauth.authentication.credentials.oauth.security;

import java.util.Map;
import java.util.Set;

public interface OAuth2AccessTokenDetails extends OAuth2TokenDetails {

    String getClientId();

    Set<String> getScopes();

    String getTokenType();

    String getUsername();

    OAuth2RefreshTokenDetails getRefreshToken();

    Map<String, String> getAdditionalInformation();

}
