package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;

import java.util.Map;

public interface OAuth2AccessTokenIntrospectionConverter {

    Map<String, Object> convertAccessToken(OAuth2AccessTokenDetails accessToken);

}
