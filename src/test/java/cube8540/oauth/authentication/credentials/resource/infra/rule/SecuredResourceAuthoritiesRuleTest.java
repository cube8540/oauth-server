package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("보호 자원 접근 권한 유효성 검사 테스트")
class SecuredResourceAuthoritiesRuleTest {

    private static List<String> RAW_AUTHORITIES = Arrays.asList("AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3", "AUTHORITY-4");

    private static Set<AuthorityCode> AUTHORITIES = RAW_AUTHORITIES.stream().map(AuthorityCode::new).collect(Collectors.toSet());

    @Test
    @DisplayName("에러 메시지 확인")
    void checkErrorMessage() {
        SecuredResourceAuthoritiesRule rule = new SecuredResourceAuthoritiesRule();

        ValidationError excepted = new ValidationError(SecuredResourceAuthoritiesRule.DEFAULT_PROPERTY, SecuredResourceAuthoritiesRule.DEFAULT_MESSAGE);
        assertEquals(excepted, rule.error());
    }

    @Nested
    @DisplayName("부여된 권한 검색 서비스가 null 일시")
    class WhenAuthoritiesReadServiceIsNull {
        private SecuredResource securedResource;
        private SecuredResourceAuthoritiesRule rule;

        @BeforeEach
        void setup() {
            this.securedResource = mock(SecuredResource.class);
            this.rule = new SecuredResourceAuthoritiesRule();

            when(securedResource.getAuthorities()).thenReturn(AUTHORITIES);
        }

        @Test
        @DisplayName("유효성 검사 결과는 false 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(securedResource));
        }
    }

    @Nested
    @DisplayName("보호 자원의 권한이 null 일시")
    class WhenSecuredResourceAuthoritiesIsNull {
        private SecuredResource securedResource;
        private SecuredResourceAuthoritiesRule rule;

        @BeforeEach
        void setup() {
            this.securedResource = mock(SecuredResource.class);
            this.rule = new SecuredResourceAuthoritiesRule();

            when(securedResource.getAuthorities()).thenReturn(null);
        }

        @Test
        @DisplayName("유효성 검사 결과는 true 가 반환되어야 한다.")
        void shouldReturnTrue() {
            assertTrue(rule.isValid(securedResource));
        }
    }

    @Nested
    @DisplayName("보호 자원의 권한이 비어 있을시")
    class WhenSecuredResourceAuthoritiesIsEmpty {
        private SecuredResource securedResource;
        private SecuredResourceAuthoritiesRule rule;

        @BeforeEach
        void setup() {
            this.securedResource = mock(SecuredResource.class);
            this.rule = new SecuredResourceAuthoritiesRule();

            when(securedResource.getAuthorities()).thenReturn(Collections.emptySet());
        }

        @Test
        @DisplayName("유효성 검사 결과는 true 가 반환되어야 한다.")
        void shouldReturnTrue() {
            assertTrue(rule.isValid(securedResource));
        }
    }

    @Nested
    @DisplayName("보호 자원의 접근 권한중 검색 되지 않는 권한이 있을시")
    class WhenAuthoritiesContainsNotSearchedAuthority {
        private SecuredResource securedResource;
        private SecuredResourceAuthoritiesRule rule;

        @BeforeEach
        void setup() {
            this.securedResource = mock(SecuredResource.class);
            this.rule = new SecuredResourceAuthoritiesRule();

            AuthorityDetailsService service = mock(AuthorityDetailsService.class);
            List<AuthorityDetails> authorities = Arrays.asList(mocking("AUTHORITY-1"), mocking("AUTHORITY-2"), mocking("AUTHORITY-3"));

            when(securedResource.getAuthorities()).thenReturn(AUTHORITIES);
            when(service.loadAuthorityByAuthorityCodes(RAW_AUTHORITIES)).thenReturn(authorities);

            this.rule.setScopeDetailsService(service);
        }

        @Test
        @DisplayName("유효성 검사 결과는 false 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(securedResource));
        }
    }

    @Nested
    @DisplayName("보호 자원의 접근 권한이 모두 검색 될 시")
    class WhenAuthoritiesAllCanSearched {
        private SecuredResource securedResource;
        private SecuredResourceAuthoritiesRule rule;

        @BeforeEach
        void setup() {
            this.securedResource = mock(SecuredResource.class);
            this.rule = new SecuredResourceAuthoritiesRule();

            AuthorityDetailsService service = mock(AuthorityDetailsService.class);
            List<AuthorityDetails> authorities = Arrays.asList(mocking("AUTHORITY-1"), mocking("AUTHORITY-2"), mocking("AUTHORITY-3"), mocking("AUTHORITY-4"));

            when(securedResource.getAuthorities()).thenReturn(AUTHORITIES);
            when(service.loadAuthorityByAuthorityCodes(RAW_AUTHORITIES)).thenReturn(authorities);

            this.rule.setScopeDetailsService(service);
        }

        @Test
        @DisplayName("유효성 검사 결과는 true 가 반환되어야 한다.")
        void shouldReturnTrue() {
            assertTrue(rule.isValid(securedResource));
        }
    }


    private AuthorityDetails mocking(String code) {
        AuthorityDetails authority = mock(AuthorityDetails.class);

        when(authority.getCode()).thenReturn(code);
        return authority;
    }

}