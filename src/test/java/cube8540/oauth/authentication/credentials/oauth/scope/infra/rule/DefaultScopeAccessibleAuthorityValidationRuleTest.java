package cube8540.oauth.authentication.credentials.oauth.scope.infra.rule;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 스코프 접근 권한 유효성 검사 클래스 테스트")
class DefaultScopeAccessibleAuthorityValidationRuleTest {

    private AuthorityDetailsService detailsService;
    private DefaultScopeAccessibleAuthorityValidationRule rule;

    @BeforeEach
    void setup() {
        this.detailsService = mock(AuthorityDetailsService.class);

        this.rule = new DefaultScopeAccessibleAuthorityValidationRule();
        this.rule.setAuthorityService(detailsService);
    }

    @Nested
    @DisplayName("권한 서비스가 null 일시")
    class WhenAuthorityDetailsServiceIsNull {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = mock(OAuth2Scope.class);
            rule.setAuthorityService(null);
        }

        @Test
        @DisplayName("유효성 검사 결과는 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(scope));
        }
    }

    @Nested
    @DisplayName("스코프의 접근 권한중 존재하지 않는 접근 권한이 있을시")
    class WhenScopesAuthorityContainsNotExistAuthority {

        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = mock(OAuth2Scope.class);

            List<AuthorityDetails> details = Arrays.asList(mocking("AUTH-1"), mocking("AUTH-2"), mocking("AUTH-3"));
            Set<AuthorityCode> scopesCode = new HashSet<>(Arrays.asList(new AuthorityCode("AUTH-1"), new AuthorityCode("AUTH-2"), new AuthorityCode("AUTH-4")));

            when(scope.getAccessibleAuthority()).thenReturn(scopesCode);
            when(detailsService.getAuthorities()).thenReturn(details);
        }

        @Test
        @DisplayName("유효성 검사 결과는 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(scope));
        }

        private AuthorityDetails mocking(String code) {
            AuthorityDetails details = mock(AuthorityDetails.class);

            when(details.getCode()).thenReturn(code);
            return details;
        }
    }

    @Nested
    @DisplayName("스코프의 접근 권한으 모두 존재하는 접근 권한일시")
    class WhenScopesAuthorityAllExisting {

        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = mock(OAuth2Scope.class);

            List<AuthorityDetails> details = Arrays.asList(mocking("AUTH-1"), mocking("AUTH-2"), mocking("AUTH-3"));
            Set<AuthorityCode> scopesCode = new HashSet<>(Arrays.asList(new AuthorityCode("AUTH-1"), new AuthorityCode("AUTH-2"), new AuthorityCode("AUTH-3")));

            when(scope.getAccessibleAuthority()).thenReturn(scopesCode);
            when(detailsService.getAuthorities()).thenReturn(details);
        }

        @Test
        @DisplayName("유효성 검사 결과는 true가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(scope));
        }

        private AuthorityDetails mocking(String code) {
            AuthorityDetails details = mock(AuthorityDetails.class);

            when(details.getCode()).thenReturn(code);
            return details;
        }
    }
}