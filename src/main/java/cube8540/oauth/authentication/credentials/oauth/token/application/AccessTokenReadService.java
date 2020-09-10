package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;

import java.util.List;

public interface AccessTokenReadService {

    List<AccessTokenDetailsWithClient> getAuthorizeAccessTokens(String username);

}
