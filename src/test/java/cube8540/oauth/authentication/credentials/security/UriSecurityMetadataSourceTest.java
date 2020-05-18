package cube8540.oauth.authentication.credentials.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("URI 베이스 보안 메타 데이터 소스 테스트")
class UriSecurityMetadataSourceTest {

    @Nested
    @DisplayName("인스턴스화")
    class Instance {
        private Map<RequestMatcher, Collection<ConfigAttribute>> metadata;
        private UriSecurityMetadataSource metadataSource;

        @BeforeEach
        void setup() {
            this.metadata = new HashMap<>();

            SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);
            when(service.loadSecurityMetadata()).thenReturn(metadata);

            this.metadataSource = new UriSecurityMetadataSource(service);
        }

        @Test
        @DisplayName("메타 데이터를 초기화 해야 한다.")
        void initializeMetadata() {
            assertEquals(metadata, metadataSource.getMetadata());
        }
    }

    @Nested
    @DisplayName("모든 메타 데이터 검색")
    class AllMetadata {
        private UriSecurityMetadataSource metadataSource;

        @BeforeEach
        void setup (){
            Map<RequestMatcher, Collection<ConfigAttribute>> metadata = new HashMap<>();

            metadata.put(mockingMatcher(), Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3")));
            metadata.put(mockingMatcher(), Arrays.asList(new SecurityConfig("TEST3"), new SecurityConfig("TEST4"), new SecurityConfig("TEST5")));
            metadata.put(mockingMatcher(), Arrays.asList(new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));

            SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);
            when(service.loadSecurityMetadata()).thenReturn(metadata);

            this.metadataSource = new UriSecurityMetadataSource(service);
        }

        @Test
        @DisplayName("모든 메타 데이터를 반환 해야 한다.")
        void shouldReturnsAllMetadata() {
            Set<ConfigAttribute> excepted = new HashSet<>(Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3"),
                    new SecurityConfig("TEST4"), new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));

            assertEquals(excepted, metadataSource.getAllConfigAttributes());
        }

        private RequestMatcher mockingMatcher() {
            return mock(RequestMatcher.class);
        }
    }

    @Nested
    @DisplayName("요청 받은 정보에 접근 가능한 메타 데이터 반환")
    class RequestCanAccessibleMetadata {
        private FilterInvocation invocation;
        private UriSecurityMetadataSource metadataSource;

        @BeforeEach
        void setup (){
            this.invocation = mock(FilterInvocation.class);

            Map<RequestMatcher, Collection<ConfigAttribute>> metadata = new HashMap<>();
            HttpServletRequest request = mock(HttpServletRequest.class);

            when(invocation.getRequest()).thenReturn(request);
            metadata.put(mockingMatcher(request, true), Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3")));
            metadata.put(mockingMatcher(request, false), Arrays.asList(new SecurityConfig("TEST3"), new SecurityConfig("TEST4"), new SecurityConfig("TEST5")));
            metadata.put(mockingMatcher(request, true), Arrays.asList(new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));

            SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);
            when(service.loadSecurityMetadata()).thenReturn(metadata);

            this.metadataSource = new UriSecurityMetadataSource(service);
        }

        @Test
        @DisplayName("접근 가능한 메타 데이터를 모두 반환해야 한다.")
        void shouldReturnsCanAccessibleAllMetadata() {
            Set<ConfigAttribute> excepted = new HashSet<>(Arrays.asList(new SecurityConfig("TEST1"), new SecurityConfig("TEST2"), new SecurityConfig("TEST3"),
                    new SecurityConfig("TEST5"), new SecurityConfig("TEST6"), new SecurityConfig("TEST7")));

            assertEquals(excepted, metadataSource.getAttributes(invocation));
        }

        private RequestMatcher mockingMatcher(HttpServletRequest request, boolean accessible) {
            RequestMatcher requestMatcher = mock(RequestMatcher.class);
            when(requestMatcher.matches(request)).thenReturn(accessible);
            return requestMatcher;
        }
    }

    @Nested
    @DisplayName("메타 데이터 리로딩")
    class MetadataReload {
        private Map<RequestMatcher, Collection<ConfigAttribute>> reloadMetadata;
        private UriSecurityMetadataSource metadataSource;

        @BeforeEach
        void setup() {
            this.reloadMetadata = new LinkedHashMap<>();

            SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);
            when(service.loadSecurityMetadata()).thenReturn(new HashMap<>());

            this.metadataSource = new UriSecurityMetadataSource(service);

            this.reloadMetadata.put(mock(RequestMatcher.class), null);
            when(service.loadSecurityMetadata()).thenReturn(reloadMetadata);
        }

        @Test
        @DisplayName("새 메타 데이터로 로딩을 해야 한다.")
        void shouldReloadMetadata() {
            metadataSource.reload();

            Map<RequestMatcher, Collection<ConfigAttribute>> metadata = metadataSource.getMetadata();
            assertEquals(reloadMetadata, metadata);
        }
    }

    @Test
    @DisplayName("지원되는 클래스 확인")
    void checkSupportedClass() {
        SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);

        UriSecurityMetadataSource source = new UriSecurityMetadataSource(service);

        assertTrue(source.supports(FilterInvocation.class));
    }

}