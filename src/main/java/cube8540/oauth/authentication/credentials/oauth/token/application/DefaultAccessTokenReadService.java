package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.token.domain.read.Oauth2AccessTokenReadRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DefaultAccessTokenReadService implements AccessTokenReadService {

    private final Oauth2AccessTokenReadRepository repository;

    @Autowired
    public DefaultAccessTokenReadService(Oauth2AccessTokenReadRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<AccessTokenDetailsWithClient> getAuthorizeAccessTokens(Authentication authentication) {
        return repository.readAccessTokenWithClientByUsername(authentication.getName());
    }
}
