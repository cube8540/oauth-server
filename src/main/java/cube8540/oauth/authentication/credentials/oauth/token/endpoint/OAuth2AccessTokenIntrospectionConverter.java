package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;

import java.util.Map;

public interface OAuth2AccessTokenIntrospectionConverter {

    Map<String, Object> convertAccessToken(OAuth2AuthorizedAccessToken accessToken);

}
