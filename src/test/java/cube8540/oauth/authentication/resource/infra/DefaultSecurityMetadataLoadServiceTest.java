package cube8540.oauth.authentication.resource.infra;

import cube8540.oauth.authentication.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.resource.domain.SecuredResource;
import cube8540.oauth.authentication.resource.domain.SecuredResourceId;
import cube8540.oauth.authentication.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.security.ScopeSecurityConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 보안 메타 데이터 로드 서비스")
class DefaultSecurityMetadataLoadServiceTest {

    static final String RESOURCE_1_ID = "RESOURCE_1";
    static final String RESOURCE_2_ID = "RESOURCE_2";
    static final String RESOURCE_3_ID = "RESOURCE_3";

    static final URI RESOURCE_1_URI = URI.create("/resource-1/**");
    static final URI RESOURCE_2_URI = URI.create("/resource-2/**");
    static final URI RESOURCE_3_URI = URI.create("/resource-3/**");

    static final ResourceMethod RESOURCE_1_METHOD = ResourceMethod.POST;
    static final ResourceMethod RESOURCE_2_METHOD = ResourceMethod.PUT;
    static final ResourceMethod RESOURCE_3_METHOD = ResourceMethod.ALL;

    static final Set<AccessibleAuthority> AUTHORITIES_1 = new HashSet<>(Arrays.asList(
            new AccessibleAuthority("AUTHORITY-1"), new AccessibleAuthority("AUTHORITY-2"), new AccessibleAuthority("AUTHORITY-3")));
    static final Set<AccessibleAuthority> AUTHORITIES_2 = new HashSet<>(Arrays.asList(
            new AccessibleAuthority("AUTHORITY-1"), new AccessibleAuthority("AUTHORITY-4"), new AccessibleAuthority("AUTHORITY-5")));
    static final Set<AccessibleAuthority> AUTHORITIES_3 = new HashSet<>(Arrays.asList(
            new AccessibleAuthority("AUTHORITY-5"), new AccessibleAuthority("AUTHORITY-6"), new AccessibleAuthority("AUTHORITY-7")));

    static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    static final String RAW_RESOURCE_URI = "/resource/**";
    static final URI RESOURCE_URI = URI.create(RAW_RESOURCE_URI);

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
        authorityCodes.forEach(auth -> attributes.add(new ScopeSecurityConfig(auth.getAuthority())));
        return attributes;
    }

    private List<SecuredResource> makeSecuredResources() {
        return Arrays.asList(makeSecuredResource(RESOURCE_1_ID, RESOURCE_1_URI, RESOURCE_1_METHOD, AUTHORITIES_1),
                makeSecuredResource(RESOURCE_2_ID, RESOURCE_2_URI, RESOURCE_2_METHOD, AUTHORITIES_2),
                makeSecuredResource(RESOURCE_3_ID, RESOURCE_3_URI, RESOURCE_3_METHOD, AUTHORITIES_3));
    }

    private SecuredResource makeSecuredResource(String resourceId, URI resourceUri, ResourceMethod resourceMethod, Set<AccessibleAuthority> authorities) {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(new SecuredResourceId(resourceId));
        when(resource.getResource()).thenReturn(resourceUri);
        when(resource.getMethod()).thenReturn(resourceMethod);
        when(resource.getAuthorities()).thenReturn(authorities);

        return resource;
    }

}