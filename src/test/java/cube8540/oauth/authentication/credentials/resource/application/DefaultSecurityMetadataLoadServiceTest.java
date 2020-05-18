package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.mockSecuredResource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 보안 메타 데이터 로드 서비스")
class DefaultSecurityMetadataLoadServiceTest {

    private static final String RESOURCE_1_ID = "RESOURCE_1";
    private static final String RESOURCE_2_ID = "RESOURCE_2";
    private static final String RESOURCE_3_ID = "RESOURCE_3";

    private static final URI RESOURCE_1_URI = URI.create("/resource-1/**");
    private static final URI RESOURCE_2_URI = URI.create("/resource-2/**");
    private static final URI RESOURCE_3_URI = URI.create("/resource-3/**");

    private static final ResourceMethod RESOURCE_1_METHOD = ResourceMethod.POST;
    private static final ResourceMethod RESOURCE_2_METHOD = ResourceMethod.PUT;
    private static final ResourceMethod RESOURCE_3_METHOD = ResourceMethod.ALL;

    private static final Set<OAuth2ScopeId> AUTHORITIES_1 = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("AUTHORITY-1"), new OAuth2ScopeId("AUTHORITY-2"), new OAuth2ScopeId("AUTHORITY-3")));
    private static final Set<OAuth2ScopeId> AUTHORITIES_2 = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("AUTHORITY-1"), new OAuth2ScopeId("AUTHORITY-4"), new OAuth2ScopeId("AUTHORITY-5")));
    private static final Set<OAuth2ScopeId> AUTHORITIES_3 = new HashSet<>(Arrays.asList(
            new OAuth2ScopeId("AUTHORITY-5"), new OAuth2ScopeId("AUTHORITY-6"), new OAuth2ScopeId("AUTHORITY-7")));

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
        List<SecuredResource> resources = Arrays.asList(mockSecuredResource().resourceId(RESOURCE_1_ID).resource(RESOURCE_1_URI).method(RESOURCE_1_METHOD).authorities(AUTHORITIES_1).build(),
                mockSecuredResource().resourceId(RESOURCE_2_ID).resource(RESOURCE_2_URI).method(RESOURCE_2_METHOD).authorities(AUTHORITIES_2).build(),
                mockSecuredResource().resourceId(RESOURCE_3_ID).resource(RESOURCE_3_URI).method(RESOURCE_3_METHOD).authorities(AUTHORITIES_3).build());

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

    private Collection<ConfigAttribute> securityConfig(Set<OAuth2ScopeId> authorityCodes) {
        return authorityCodes.stream().map(OAuth2ScopeId::getValue).map(SecurityConfig::new).collect(Collectors.toList());
    }

}