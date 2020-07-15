package cube8540.oauth.authentication.credentials.security;

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
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

    private Collection<ConfigAttribute> authorityToConfigAttribute(Set<AccessibleAuthority> authorities) {
        Collection<ConfigAttribute> configAttributes = new HashSet<>();

        Optional.ofNullable(authorities).orElse(Collections.emptySet())
                .forEach(auth -> configAttributes.add(new ScopeSecurityConfig(auth.getAuthority())));

        return configAttributes;
    }
}
