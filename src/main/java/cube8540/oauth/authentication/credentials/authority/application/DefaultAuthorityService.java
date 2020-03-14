package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.BasicAuthorityService;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class DefaultAuthorityService implements BasicAuthorityService {

    private AuthorityRepository repository;

    @Autowired
    public DefaultAuthorityService(AuthorityRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<AuthorityCode> getBasicAuthority() {
        return repository.findByBasicTrue().stream().map(Authority::getCode).collect(Collectors.toList());
    }
}
