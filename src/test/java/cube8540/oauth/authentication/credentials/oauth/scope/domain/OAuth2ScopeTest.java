package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.oauth.error.ScopeInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.ACCESSIBLE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.GRANTED_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.NOT_ACCESSIBLE_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.RAW_SCOPE_ID;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.mocKValidationRule;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.mockAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeTestHelper.mockValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("OAuth2 스코프 테스트")
class OAuth2ScopeTest {

    @Nested
    @DisplayName("접근 가능한 권한 추가")
    class AddAccessibleAuthority {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
        }

        @Test
        @DisplayName("인자로 받은 권한을 저장해야 한다.")
        void shouldSaveGivenAuthority() {
            scope.addAccessibleAuthority(AUTHORITY_CODE);

            assertTrue(scope.getAccessibleAuthority().contains(AUTHORITY_CODE));
        }
    }

    @Nested
    @DisplayName("접근 권한 제거")
    class RemoveAccessibleAuthority {
        private OAuth2Scope scope;

        @BeforeEach
        void setup() {
            this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
            scope.addAccessibleAuthority(AUTHORITY_CODE);
        }

        @Test
        @DisplayName("인자로 받은 권한을 삭제한다.")
        void shouldRemovedRequestingAuthority() {
            scope.removeAccessibleAuthority(AUTHORITY_CODE);

            assertFalse(scope.getAccessibleAuthority().contains(AUTHORITY_CODE));
        }
    }

    @Nested
    @DisplayName("접근 가능 확인")
    class TestAccessible {

        @Nested
        @DisplayName("스코프의 접근 가능한 권한이 null일시")
        class WhenScopeAccessibleAuthorityIsNull {
            private OAuth2Scope scope;
            private Authentication authentication;

            @BeforeEach
            void setup() {
                this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
                this.authentication = mockAuthentication(GRANTED_AUTHORITIES);
            }

            @Test
            @DisplayName("접근 가능 여부는 false 가 반환되어야 한다.")
            void shouldReturnsFalse() {
                assertFalse(scope.isAccessible(authentication));
            }
        }

        @Nested
        @DisplayName("스코프의 접근 가능한 권한이 null이 아닐시")
        class WhenScopeAccessibleAuthorityIsNotNull {

            @Nested
            @DisplayName("인증 정보에 접근 가능한 권한이 없을시")
            class WhenAuthenticationNotHaveAccessibleAuthority {
                private OAuth2Scope scope;
                private Authentication authentication;

                @BeforeEach
                void setup() {
                    this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
                    this.authentication = mockAuthentication(NOT_ACCESSIBLE_AUTHORITIES);

                    ACCESSIBLE_AUTHORITY.forEach(auth -> scope.addAccessibleAuthority(auth));
                }

                @Test
                @DisplayName("접근 가능 여부는 false 가 반환되어야 한다.")
                void shouldReturnsFalse() {
                    assertFalse(scope.isAccessible(authentication));
                }
            }

            @Nested
            @DisplayName("인증 정보에 접근 가능한 권한이 있을시")
            class WhenAuthenticationHaveAccessibleAuthority {
                private OAuth2Scope scope;
                private Authentication authentication;

                @BeforeEach
                void setup() {
                    this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
                    this.authentication = mockAuthentication(GRANTED_AUTHORITIES);

                    ACCESSIBLE_AUTHORITY.forEach(auth -> scope.addAccessibleAuthority(auth));
                }

                @Test
                @DisplayName("접근 가능 여부는 true 가 반환되어야 한다.")
                void shouldReturnsTrue() {
                    assertTrue(scope.isAccessible(authentication));
                }
            }
        }
    }

    @Nested
    @DisplayName("스코프 유효성 체크")
    class ScopeValidation {

        @Nested
        @DisplayName("스코프 아이디가 유효하지 않을시")
        class WhenScopeIsNotAllowed {
            private OAuth2Scope scope;
            private OAuth2ScopeValidationPolicy policy;
            private ValidationError error;

            @BeforeEach
            void setup() {
                this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
                this.error = new ValidationError("id", "invalid scope id");

                ValidationRule<OAuth2Scope> scopeIdRule = mocKValidationRule().configValidationFalse(scope).error(error).build();
                ValidationRule<OAuth2Scope> accessibleRule = mocKValidationRule().configValidationTrue(scope).build();

                this.policy = mockValidationPolicy().scopeIdRule(scopeIdRule).accessibleAuthorityRule(accessibleRule).build();
            }

            @Test
            @DisplayName("ScopeInvalidException 이 발생해야 한다.")
            void shouldThrowScopeInvalidException() {
                assertThrows(ScopeInvalidException.class, () -> scope.validate(policy));
            }

            @Test
            @DisplayName("스코프 아이디 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsScopeIdErrorMessage() {
                ScopeInvalidException exception = assertThrows(ScopeInvalidException.class, () -> scope.validate(policy));
                assertTrue(exception.getErrors().contains(error));
            }
        }

        @Nested
        @DisplayName("스코프 접근 권한이 유효하지 않을시")
        class WhenScopeAccessibleAuthorityNotAllowed {
            private OAuth2Scope scope;
            private OAuth2ScopeValidationPolicy policy;
            private ValidationError error;

            @BeforeEach
            void setup() {
                this.scope = new OAuth2Scope(RAW_SCOPE_ID, DESCRIPTION);
                this.error = new ValidationError("accessibleAuthority", "invalid authority");

                ValidationRule<OAuth2Scope> scopeIdRule = mocKValidationRule().configValidationTrue(scope).build();
                ValidationRule<OAuth2Scope> accessibleRule = mocKValidationRule().configValidationFalse(scope).error(error).build();

                this.policy = mockValidationPolicy().scopeIdRule(scopeIdRule).accessibleAuthorityRule(accessibleRule).build();
            }

            @Test
            @DisplayName("ScopeInvalidException 이 발생해야 한다.")
            void shouldThrowScopeInvalidException() {
                assertThrows(ScopeInvalidException.class, () -> scope.validate(policy));
            }

            @Test
            @DisplayName("스코프 접근 권한 유효성에 관련된 에러가 포함되어야 한다.")
            void shouldContainsAccessibleAuthorityErrorMessage() {
                ScopeInvalidException exception = assertThrows(ScopeInvalidException.class, () -> scope.validate(policy));
                assertTrue(exception.getErrors().contains(error));
            }
        }
    }
}