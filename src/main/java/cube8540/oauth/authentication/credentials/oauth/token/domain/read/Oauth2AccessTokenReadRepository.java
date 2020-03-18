package cube8540.oauth.authentication.credentials.oauth.token.domain.read;

import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;

import java.util.List;

public interface Oauth2AccessTokenReadRepository {

    List<AccessTokenDetailsWithClient> readAccessTokenWithClientByUsername(String username);

}
