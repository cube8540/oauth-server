package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceDetails;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceReadService;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccessibleResourceRuleTest {
    private static Set<SecuredResourceId> ACCESSIBLE_RESOURCES = new HashSet<>(Arrays.asList(
            new SecuredResourceId("RESOURCE-1"),
            new SecuredResourceId("RESOURCE-2"),
            new SecuredResourceId("RESOURCE-3"),
            new SecuredResourceId("RESOURCE-4")));

    @Test
    @DisplayName("에러 메시지 확인")
    void checkErrorMessage() {
        AccessibleResourceRule rule = new AccessibleResourceRule();

        ValidationError excepted = new ValidationError(AccessibleResourceRule.DEFAULT_PROPERTY, AccessibleResourceRule.DEFAULT_MESSAGE);
        assertEquals(excepted, rule.error());
    }

    @Nested
    @DisplayName("보호 자원 검색 서비스가 null 일시")
    class SecuredResourceReadServiceIsNull {
        private Authority authority;
        private AccessibleResourceRule rule;

        @BeforeEach
        void setup() {
            this.rule = new AccessibleResourceRule();
            this.authority = mock(Authority.class);
            when(authority.getAccessibleResources()).thenReturn(ACCESSIBLE_RESOURCES);
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 false 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(authority));
        }
    }

    @Nested
    @DisplayName("권한의 접근 자원이 null 일시")
    class WhenAuthorityAccessibleResourceIsNull {
        private Authority authority;
        private AccessibleResourceRule rule;

        @BeforeEach
        void setup() {
            this.rule = new AccessibleResourceRule();
            this.authority = mock(Authority.class);
            when(authority.getAccessibleResources()).thenReturn(null);
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 true 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertTrue(rule.isValid(authority));
        }
    }

    @Nested
    @DisplayName("권한의 접근 자원이 비어 있을시")
    class WhenAuthorityAccessibleResourceIsEmpty {
        private Authority authority;
        private AccessibleResourceRule rule;

        @BeforeEach
        void setup() {
            this.rule = new AccessibleResourceRule();
            this.authority = mock(Authority.class);
            when(authority.getAccessibleResources()).thenReturn(Collections.emptySet());
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 true 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertTrue(rule.isValid(authority));
        }
    }

    @Nested
    @DisplayName("권한의 접근 자원중 검색되지 않은 접근 자원이 있을시")
    class WhenAccessibleResourceContainsNotSearchedResource {
        private Authority authority;
        private AccessibleResourceRule rule;

        @BeforeEach
        void setup() {
            this.rule = new AccessibleResourceRule();
            this.authority = mock(Authority.class);
            SecuredResourceReadService service = mock(SecuredResourceReadService.class);
            List<SecuredResourceDetails> resources = Arrays.asList(mocking("RESOURCE-1"), mocking("RESOURCE-2"), mocking("RESOURCE-3"));

            when(service.getResources()).thenReturn(resources);
            when(authority.getAccessibleResources()).thenReturn(ACCESSIBLE_RESOURCES);

            this.rule.setSecuredResourceReadService(service);
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 false 가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(authority));
        }
    }

    @Nested
    @DisplayName("권한의 접근 자원이 모두 검색될시")
    class WhenAccessibleResourceAllCanSearched {
        private Authority authority;
        private AccessibleResourceRule rule;

        @BeforeEach
        void setup() {
            this.rule = new AccessibleResourceRule();
            this.authority = mock(Authority.class);
            SecuredResourceReadService service = mock(SecuredResourceReadService.class);
            List<SecuredResourceDetails> resources = Arrays.asList(mocking("RESOURCE-1"), mocking("RESOURCE-2"), mocking("RESOURCE-3"), mocking("RESOURCE-4"));

            when(service.getResources()).thenReturn(resources);
            when(authority.getAccessibleResources()).thenReturn(ACCESSIBLE_RESOURCES);

            this.rule.setSecuredResourceReadService(service);
        }

        @Test
        @DisplayName("유효성 검사 결과는 반드시 true 가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(authority));
        }
    }

    private SecuredResourceDetails mocking(String id) {
        SecuredResourceDetails details = mock(SecuredResourceDetails.class);

        when(details.getResourceId()).thenReturn(id);
        return details;
    }
}