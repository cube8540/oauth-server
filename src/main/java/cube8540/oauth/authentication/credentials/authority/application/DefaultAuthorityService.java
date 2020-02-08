package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;

import java.util.List;
import java.util.stream.Collectors;

public class DefaultAuthorityService implements BasicAuthorityService {

    private AuthorityRepository repository;

    public DefaultAuthorityService(AuthorityRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<AuthorityCode> getBasicAuthority() {
        return repository.findByBasicTrue().stream().map(Authority::getCode).collect(Collectors.toList());
    }
}
