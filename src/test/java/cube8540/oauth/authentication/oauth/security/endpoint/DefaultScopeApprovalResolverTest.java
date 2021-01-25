package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.error.UserDeniedAuthorizationException;
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 스코프 허용 Resolver 클래스 테스트")
class DefaultScopeApprovalResolverTest {

    private static final Set<String> STORED_SCOPE = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));

    private DefaultScopeApprovalResolver resolver;

    @BeforeEach
    void setup() {
        this.resolver = new DefaultScopeApprovalResolver();
    }

    @Test
    @DisplayName("허용 되는 스코프가 없을 때")
    void notHasApprovalScope() {
        AuthorizationRequest authorizationRequest = mock(AuthorizationRequest.class);
        Map<String, String> approvalScopes = new HashMap<>();

        approvalScopes.put("SCOPE-1", "false"); // 소문자
        approvalScopes.put("SCOPE-2", "FALSE"); // 대문자
        approvalScopes.put("SCOPE-3", "false"); // 비허용
        approvalScopes.put("ANY", "ANY"); // 스코프가 아닌 다른값
        when(authorizationRequest.getRequestScopes()).thenReturn(STORED_SCOPE);

        assertThrows(UserDeniedAuthorizationException.class, () -> resolver.resolveApprovalScopes(authorizationRequest, approvalScopes));
    }

    @Test
    @DisplayName("허용 되는 스코프 추출")
    void extractApprovalScope() {
        AuthorizationRequest authorizationRequest = mock(AuthorizationRequest.class);
        Map<String, String> approvalScopes = new HashMap<>();

        approvalScopes.put("SCOPE-1", "true"); // 소문자
        approvalScopes.put("SCOPE-2", "TRUE"); // 대문자
        approvalScopes.put("SCOPE-3", "false"); // 비허용
        approvalScopes.put("ANY", "ANY"); // 스코프가 아닌 다른값
        when(authorizationRequest.getRequestScopes()).thenReturn(STORED_SCOPE);

        Set<String> resolvedApprovalScopes = resolver.resolveApprovalScopes(authorizationRequest, approvalScopes);
        Set<String> exceptedApprovalScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2"));
        assertEquals(exceptedApprovalScopes, resolvedApprovalScopes);
    }
}