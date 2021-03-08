package cube8540.oauth.authentication.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityApplicationTestHelper {

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
}
