package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.error.UserDeniedAuthorizationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
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

    @Nested
    @DisplayName("허용되는 스코프 추출")
    class ExtractApprovalScope {

        private AuthorizationRequest authorizationRequest;
        private Map<String, String> approvalScopes;

        @BeforeEach
        void setup() {
            this.authorizationRequest = mock(AuthorizationRequest.class);
            this.approvalScopes = new HashMap<>();

            this.approvalScopes.put("SCOPE-1", "true"); // 소문자
            this.approvalScopes.put("SCOPE-2", "TRUE"); // 대문자
            this.approvalScopes.put("SCOPE-3", "false"); // 비허용
            this.approvalScopes.put("ANY", "ANY"); // 스코프가 아닌 다른값

            when(authorizationRequest.getRequestScopes()).thenReturn(STORED_SCOPE);
        }

        @Nested
        @DisplayName("허용한 스코프가 없을시")
        class WhenNoScopeAllowed {
            private Map<String, String> approvalScopes;

            @BeforeEach
            void setup() {
                this.approvalScopes = new HashMap<>();
                this.approvalScopes.put("SCOPE-1", "false"); // 소문자
                this.approvalScopes.put("SCOPE-2", "FALSE"); // 대문자
                this.approvalScopes.put("SCOPE-3", "false"); // 비허용
                this.approvalScopes.put("ANY", "ANY"); // 스코프가 아닌 다른값
            }

            @Test
            @DisplayName("UserDeniedAuthorizationException을 발생시켜야 한다.")
            void shouldThrowsUserDeniedAuthorizationException() {
                assertThrows(UserDeniedAuthorizationException.class, () -> resolver.resolveApprovalScopes(authorizationRequest, approvalScopes));
            }
        }

        @Test
        @DisplayName("허용된 스코프만 반환해야 한다.")
        void shouldReturnsOnlyApprovalScope() {
            Set<String> resolvedApprovalScopes = resolver.resolveApprovalScopes(authorizationRequest, approvalScopes);

            Set<String> exceptedApprovalScopes = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2"));
            assertEquals(exceptedApprovalScopes, resolvedApprovalScopes);
        }
    }

}