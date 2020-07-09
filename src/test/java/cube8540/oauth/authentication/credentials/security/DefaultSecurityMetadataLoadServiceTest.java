package cube8540.oauth.authentication.credentials.security;

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.AUTHORITIES_1;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.AUTHORITIES_2;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.AUTHORITIES_3;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_1_METHOD;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_1_URI;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_2_METHOD;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_2_URI;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_3_METHOD;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.RESOURCE_3_URI;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.makeSecuredResources;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 보안 메타 데이터 로드 서비스")
class DefaultSecurityMetadataLoadServiceTest {

    private SecuredResourceRepository repository;

    private DefaultSecurityMetadataLoadService service;

    @BeforeEach
    void setup() {
        this.repository = mock(SecuredResourceRepository.class);
        this.service = new DefaultSecurityMetadataLoadService(repository);
    }

    @Test
    @DisplayName("보호 자원 접근 권한 메타 데이터 로드")
    void loadSecuredResourceAuthorityMetadata() {
        List<SecuredResource> resources = makeSecuredResources();

        when(repository.findAll()).thenReturn(resources);

        Map<RequestMatcher, Collection<ConfigAttribute>> metadata = service.loadSecurityMetadata();
        assertEquals(metadata.get(requestMatcher(RESOURCE_1_URI, RESOURCE_1_METHOD)), securityConfig(AUTHORITIES_1));
        assertEquals(metadata.get(requestMatcher(RESOURCE_2_URI, RESOURCE_2_METHOD)), securityConfig(AUTHORITIES_2));
        assertEquals(metadata.get(requestMatcher(RESOURCE_3_URI, RESOURCE_3_METHOD)), securityConfig(AUTHORITIES_3));
    }

    private RequestMatcher requestMatcher(URI uri, ResourceMethod method) {
        if (method.equals(ResourceMethod.ALL)) {
            return new AntPathRequestMatcher(uri.toString());
        } else {
            return new AntPathRequestMatcher(uri.toString(), method.toString());
        }
    }

    private Collection<ConfigAttribute> securityConfig(Set<AccessibleAuthority> authorityCodes) {
        Collection<ConfigAttribute> attributes = new HashSet<>();
        authorityCodes.stream().filter(auth -> auth.getAuthorityType().equals(AccessibleAuthority.AuthorityType.OAUTH2_SCOPE)).forEach(auth -> attributes.add(new ScopeSecurityConfig(auth.getAuthority())));
        authorityCodes.stream().filter(auth -> auth.getAuthorityType().equals(AccessibleAuthority.AuthorityType.AUTHORITY)).forEach(auth -> attributes.add(new RoleSecurityConfig(auth.getAuthority())));

        return attributes;
    }

}