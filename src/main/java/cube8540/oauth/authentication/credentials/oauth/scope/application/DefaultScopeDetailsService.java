package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class DefaultScopeDetailsService implements OAuth2ScopeDetailsService {

    private final OAuth2ScopeRepository repository;

    @Autowired
    public DefaultScopeDetailsService(OAuth2ScopeRepository repository) {
        this.repository = repository;
    }

    @Override
    public Collection<OAuth2ScopeDetails> loopScopes(Collection<String> scopeIds) {
        List<OAuth2ScopeId> scopeIn = scopeIds.stream()
                .map(OAuth2ScopeId::new).collect(Collectors.toList());
        return repository.findByIdIn(scopeIn).stream()
                .map(DetailsOAuth2ScopeDetails::new).collect(Collectors.toList());
    }
}
