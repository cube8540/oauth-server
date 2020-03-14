package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.security.SecurityMetadataLoadService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DefaultSecurityMetadataLoadService implements SecurityMetadataLoadService {

    private final SecuredResourceRepository repository;

    @Autowired
    public DefaultSecurityMetadataLoadService(SecuredResourceRepository repository) {
        this.repository = repository;
    }

    @Override
    public Map<RequestMatcher, Collection<ConfigAttribute>> loadSecurityMetadata() {
        return repository.findAll().stream().collect(Collectors.toMap(this::requestMatcher, resource -> authorityToConfigAttribute(resource.getAuthorities())));
    }

    private RequestMatcher requestMatcher(SecuredResource securedResource) {
        if (securedResource.getMethod().equals(ResourceMethod.ALL)) {
            return new AntPathRequestMatcher(securedResource.getResource().toString());
        } else {
            return new AntPathRequestMatcher(securedResource.getResource().toString(), securedResource.getMethod().toString());
        }
    }

    private Collection<ConfigAttribute> authorityToConfigAttribute(Set<AuthorityCode> authorities) {
        return Optional.ofNullable(authorities).orElse(Collections.emptySet())
                .stream().map(AuthorityCode::getValue).map(SecurityConfig::new).collect(Collectors.toList());
    }
}
