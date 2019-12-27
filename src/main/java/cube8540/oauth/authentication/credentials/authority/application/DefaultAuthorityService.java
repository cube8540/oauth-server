package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;

import java.util.List;

public class DefaultAuthorityService implements BasicAuthorityService {

    private AuthorityRepository repository;

    public DefaultAuthorityService(AuthorityRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<Authority> getBasicAuthority() {
        return repository.findByBasicTrue();
    }
}
