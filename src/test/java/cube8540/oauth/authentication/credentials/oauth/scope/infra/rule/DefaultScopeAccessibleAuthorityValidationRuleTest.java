package cube8540.oauth.authentication.credentials.oauth.scope.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 스코프 접근 권한 유효성 검사 클래스 테스트")
class DefaultScopeAccessibleAuthorityValidationRuleTest {

    private static final List<String> RAW_GIVEN_SCOPES = Arrays.asList("AUTH-1", "AUTH-2", "AUTH-3");
    private static final Set<AuthorityCode> GIVEN_SCOPES = RAW_GIVEN_SCOPES.stream().map(AuthorityCode::new).collect(Collectors.toSet());

    private AuthorityDetailsService detailsService;
    private DefaultScopeAccessibleAuthorityValidationRule rule;

    @BeforeEach
    void setup() {
        this.detailsService = mock(AuthorityDetailsService.class);

        this.rule = new DefaultScopeAccessibleAuthorityValidationRule();
        this.rule.setScopeDetailsServices(detailsService);
    }

    @Nested
    @DisplayName("권한 서비스가 null 일시")
    class WhenAuthorityDetailsServiceIsNull {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = mock(OAuth2Scope.class);
            rule.setScopeDetailsServices(null);
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

            List<AuthorityDetails> details = Arrays.asList(mocking("AUTH-1"), mocking("AUTH-2"));

            when(scope.getAccessibleAuthority()).thenReturn(GIVEN_SCOPES);
            when(detailsService.loadAuthorityByAuthorityCodes(RAW_GIVEN_SCOPES)).thenReturn(details);
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
    @DisplayName("스코프의 접근 권한이 모두 존재하는 접근 권한일시")
    class WhenScopesAuthorityAllExisting {

        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = mock(OAuth2Scope.class);

            List<AuthorityDetails> details = Arrays.asList(mocking("AUTH-1"), mocking("AUTH-2"), mocking("AUTH-3"));

            when(scope.getAccessibleAuthority()).thenReturn(GIVEN_SCOPES);
            when(detailsService.loadAuthorityByAuthorityCodes(RAW_GIVEN_SCOPES)).thenReturn(details);
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