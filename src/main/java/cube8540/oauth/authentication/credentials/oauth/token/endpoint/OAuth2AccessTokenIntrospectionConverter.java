package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;

import java.util.Map;

public interface OAuth2AccessTokenIntrospectionConverter {

    Map<String, Object> convertAccessToken(OAuth2AccessTokenDetails accessToken);

}
