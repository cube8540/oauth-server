package cube8540.oauth.authentication.credentials.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.makeAccessibleMetadata;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.makeAllMetadata;
import static cube8540.oauth.authentication.credentials.security.SecurityApplicationTestHelper.makeMetadata;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("URI 베이스 보안 메타 데이터 소스 테스트")
class UriSecurityMetadataSourceTest {

    @Test
    @DisplayName("클래스 인스터스화시 메타 데이터 초기화")
    void initializeMetadataWhenClassInstance() {
        Map<RequestMatcher, Collection<ConfigAttribute>> metadata = Collections.emptyMap();
        SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);

        when(service.loadSecurityMetadata()).thenReturn(metadata);

        UriSecurityMetadataSource source = new UriSecurityMetadataSource(service);
        assertEquals(metadata, source.getMetadata());
    }

    @Test
    @DisplayName("모든 메타 데이터 반환")
    void returnAllMetadata() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<RequestMatcher, Collection<ConfigAttribute>> metadata = makeMetadata(request);
        SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);

        when(service.loadSecurityMetadata()).thenReturn(metadata);

        UriSecurityMetadataSource source = new UriSecurityMetadataSource(service);
        Set<ConfigAttribute> excepted = makeAllMetadata();
        assertEquals(excepted, source.getAllConfigAttributes());
    }

    @Test
    @DisplayName("요청 받은 정보에 접근 가능한 메타 데이터 반환")
    void returnAccessibleMetadata() {
        FilterInvocation invocation = mock(FilterInvocation.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<RequestMatcher, Collection<ConfigAttribute>> metadata = makeMetadata(request);
        SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);

        when(invocation.getRequest()).thenReturn(request);
        when(service.loadSecurityMetadata()).thenReturn(metadata);

        UriSecurityMetadataSource source = new UriSecurityMetadataSource(service);
        Set<ConfigAttribute> excepted = makeAccessibleMetadata();
        assertEquals(excepted, source.getAttributes(invocation));
    }

    @Test
    @DisplayName("메타 데이터 리로드")
    void reloadMetadata() {
        Map<RequestMatcher, Collection<ConfigAttribute>> originalMetadata = Collections.emptyMap();
        Map<RequestMatcher, Collection<ConfigAttribute>> reloadMetadata = Collections.singletonMap(mock(RequestMatcher.class), Collections.emptyList());
        SecurityMetadataLoadService metadataLoadService = mock(SecurityMetadataLoadService.class);
        when(metadataLoadService.loadSecurityMetadata()).thenReturn(originalMetadata);
        UriSecurityMetadataSource source = new UriSecurityMetadataSource(metadataLoadService);

        when(metadataLoadService.loadSecurityMetadata()).thenReturn(reloadMetadata);

        source.reload();
        assertEquals(reloadMetadata, source.getMetadata());
    }

    @Test
    @DisplayName("지원 되는 클래스 확인")
    void checkSupportedClass() {
        SecurityMetadataLoadService service = mock(SecurityMetadataLoadService.class);

        UriSecurityMetadataSource source = new UriSecurityMetadataSource(service);

        assertTrue(source.supports(FilterInvocation.class));
    }

}