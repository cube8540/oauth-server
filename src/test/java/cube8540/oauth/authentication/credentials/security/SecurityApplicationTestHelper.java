package cube8540.oauth.authentication.credentials.security;

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceId;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityApplicationTestHelper {

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

    static RequestMatcher makeMatcher(HttpServletRequest request, boolean accessible) {
        RequestMatcher matcher = mock(RequestMatcher.class);

        when(matcher.matches(request)).thenReturn(accessible);

        return matcher;
    }

    static Map<RequestMatcher, Collection<ConfigAttribute>> makeMetadata(HttpServletRequest request) {
        Map<RequestMatcher, Collection<ConfigAttribute>> metadata = new HashMap<>();

        metadata.put(makeMatcher(request, true), Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3")));
        metadata.put(makeMatcher(request, false), Arrays.asList(new SecurityConfig("TEST3"), new SecurityConfig("TEST4"), new SecurityConfig("TEST5")));
        metadata.put(makeMatcher(request, true), Arrays.asList(new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));

        return metadata;
    }

    static Set<ConfigAttribute> makeAllMetadata() {
        return new HashSet<>(Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3"),
                new SecurityConfig("TEST4"), new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));
    }

    static Set<ConfigAttribute> makeAccessibleMetadata() {
        return new HashSet<>(Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3"),
                new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));
    }

    static List<SecuredResource> makeSecuredResources() {
        return Arrays.asList(makeSecuredResource(RESOURCE_1_ID, RESOURCE_1_URI, RESOURCE_1_METHOD, AUTHORITIES_1),
                makeSecuredResource(RESOURCE_2_ID, RESOURCE_2_URI, RESOURCE_2_METHOD, AUTHORITIES_2),
                makeSecuredResource(RESOURCE_3_ID, RESOURCE_3_URI, RESOURCE_3_METHOD, AUTHORITIES_3));
    }

    static SecuredResource makeSecuredResource(String resourceId, URI resourceUri, ResourceMethod resourceMethod, Set<AccessibleAuthority> authorities) {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(new SecuredResourceId(resourceId));
        when(resource.getResource()).thenReturn(resourceUri);
        when(resource.getMethod()).thenReturn(resourceMethod);
        when(resource.getAuthorities()).thenReturn(authorities);

        return resource;
    }
}
