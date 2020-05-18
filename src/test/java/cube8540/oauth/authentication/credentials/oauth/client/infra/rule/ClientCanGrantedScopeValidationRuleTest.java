package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2AccessibleScopeDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 스코프 부여 가능 여부를 확인하는 클래스 테스트")
class ClientCanGrantedScopeValidationRuleTest {

    private ClientCanGrantedScopeValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new ClientCanGrantedScopeValidationRule();
    }

    @Nested
    @DisplayName("스코프 검색 서비스가 null일시")
    class ScopeServicesIsNull {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("시큐리티 컨텍스트가 null일시")
    class SecurityContextIsNull {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);
        }

        @Test
        @DisplayName("유효성 감사 결과는 반드시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트의 스코프가 null일시")
    class WhenClientScopesIsNull {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            OAuth2AccessibleScopeDetailsService scopeDetailsService = mock(OAuth2AccessibleScopeDetailsService.class);
            SecurityContext securityContext = mock(SecurityContext.class);
            this.client = mock(OAuth2Client.class);

            when(client.getScopes()).thenReturn(null);
            rule.setScopeDetailsService(scopeDetailsService);
            rule.setSecurityContext(securityContext);
        }

        @Test
        @DisplayName("유효성 감사 결과는 반드시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트의 스코프가 비어있을시")
    class WhenClientScopesIsEmpty {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            OAuth2AccessibleScopeDetailsService scopeDetailsService = mock(OAuth2AccessibleScopeDetailsService.class);
            SecurityContext securityContext = mock(SecurityContext.class);
            this.client = mock(OAuth2Client.class);

            when(client.getScopes()).thenReturn(Collections.emptySet());
            rule.setScopeDetailsService(scopeDetailsService);
            rule.setSecurityContext(securityContext);
        }

        @Test
        @DisplayName("유효성 감사 결과는 반드시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트의 스코프중 인증 받은 유저가 접근 할 수 없는 스코프가 있을시")
    class WhenScopesOnTheClientAreInaccessibleToTheAuthenticatedUser {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            Authentication authentication = mock(Authentication.class);
            OAuth2AccessibleScopeDetailsService scopeDetailsService = mock(OAuth2AccessibleScopeDetailsService.class);
            SecurityContext securityContext = mock(SecurityContext.class);
            List<AuthorityDetails> scopes = Arrays.asList(mocking("SCOPE-1"), mocking("SCOPE-2"), mocking("SCOPE-3"));
            Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-6")));

            this.client = mock(OAuth2Client.class);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(scopeDetailsService.readAccessibleScopes(authentication)).thenReturn(scopes);
            when(client.getScopes()).thenReturn(clientScopes);

            rule.setScopeDetailsService(scopeDetailsService);
            rule.setSecurityContext(securityContext);
        }

        @Test
        @DisplayName("유효성 감사 결과는 반드시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }

        private AuthorityDetails mocking(String scopeId) {
            AuthorityDetails scopeDetails = mock(AuthorityDetails.class);

            when(scopeDetails.getCode()).thenReturn(scopeId);
            return scopeDetails;
        }
    }

    @Nested
    @DisplayName("클라이언트의 스코프가 모두 유저가 접근 할 수 있는 스코프일시")
    class WhenScopeOnTheClientAreAccessibleToTheAuthenticatedUser {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            Authentication authentication = mock(Authentication.class);
            OAuth2AccessibleScopeDetailsService scopeDetailsService = mock(OAuth2AccessibleScopeDetailsService.class);
            SecurityContext securityContext = mock(SecurityContext.class);
            List<AuthorityDetails> scopes = Arrays.asList(mocking("SCOPE-1"), mocking("SCOPE-2"), mocking("SCOPE-3"));
            Set<AuthorityCode> clientScopes = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-3")));

            this.client = mock(OAuth2Client.class);

            when(securityContext.getAuthentication()).thenReturn(authentication);
            when(scopeDetailsService.readAccessibleScopes(authentication)).thenReturn(scopes);
            when(client.getScopes()).thenReturn(clientScopes);

            rule.setScopeDetailsService(scopeDetailsService);
            rule.setSecurityContext(securityContext);
        }

        @Test
        @DisplayName("유효성 감사 결과는 반드시 true가 반환되어야 한다.")
        void shouldReturnTrue() {
            assertTrue(rule.isValid(client));
        }

        private AuthorityDetails mocking(String scopeId) {
            AuthorityDetails scopeDetails = mock(AuthorityDetails.class);

            when(scopeDetails.getCode()).thenReturn(scopeId);
            return scopeDetails;
        }
    }

}