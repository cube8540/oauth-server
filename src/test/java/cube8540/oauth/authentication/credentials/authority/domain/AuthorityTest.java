package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.ERROR_MESSAGE;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.ERROR_PROPERTY;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.mockAuthorityValidationPolicy;
import static cube8540.oauth.authentication.credentials.authority.domain.AuthorityTestHelper.mockAuthorityValidationRule;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("권한 도메인 테스트")
class AuthorityTest {

    @Nested
    @DisplayName("기본 권한 설정")
    class SettingBasicAuthority {

        @Nested
        @DisplayName("기본 권한으로 설정시")
        class ConfigBasicAuthority {
            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
            }

            @Test
            @DisplayName("기본 권한 여부가 true 로 설정되어야 한다.")
            void shouldSettingBasicAuthority() {
                authority.settingBasicAuthority();

                assertTrue(authority.isBasic());
            }
        }

        @Nested
        @DisplayName("일반 권한으로 설정")
        class ConfigNotBasicAuthority {

            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
            }

            @Test
            @DisplayName("기본 권한 여부가 false 로 설정되어야 한다.")
            void shouldSettingNotBasicAuthority() {
                authority.settingNotBasicAuthority();

                assertFalse(authority.isBasic());
            }
        }
    }

    @Nested
    @DisplayName("접근 자원 추가")
    class AddAccessibleResource {
        private Authority authority;

        @BeforeEach
        void setup() {
            this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
        }

        @Test
        @DisplayName("인자로 받은 접근 자원을 추가 해야 한다.")
        void shouldAddGivenAccessibleResource() {
            this.authority.addAccessibleResource(RESOURCE_ID);

            assertTrue(authority.getAccessibleResources().contains(RESOURCE_ID));
        }
    }

    @Nested
    @DisplayName("접근 자원 삭제")
    class RemoveAccessibleResource {
        private Authority authority;

        @BeforeEach
        void setup() {
            this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
            this.authority.addAccessibleResource(RESOURCE_ID);
        }

        @Test
        @DisplayName("인자로 받은 접근 자원을 삭제 해야 한다.")
        void shouldRemoveGivenAccessibleResource() {
            this.authority.removeAccessibleResource(RESOURCE_ID);

            assertFalse(authority.getAccessibleResources().contains(RESOURCE_ID));
        }
    }

    @Nested
    @DisplayName("유효성 검사")
    class Validation {

        @Nested
        @DisplayName("허용되지 않는 코드 일시")
        class WhenNotAllowedCode {
            private AuthorityValidationPolicy policy;
            private ValidationError errorMessage;
            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<Authority> codeRule = mockAuthorityValidationRule().configReturnFalse(authority).validationError(errorMessage).build();
                ValidationRule<Authority> accessibleResourceRule = mockAuthorityValidationRule().configReturnTrue(authority).build();

                this.policy = mockAuthorityValidationPolicy().codeRule(codeRule).accessibleResourceRule(accessibleResourceRule).build();
            }

            @Test
            @DisplayName("AuthorityInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsAuthorityInvalidExceptionAndContainsErrorCodes() {
                AuthorityInvalidException exception = assertThrows(AuthorityInvalidException.class, () -> authority.validation(policy));

                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }

        @Nested
        @DisplayName("허용되지 않는 접근 자원 일시")
        class WheNotAllowedAccessibleResource {
            private AuthorityValidationPolicy policy;
            private ValidationError errorMessage;
            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = new Authority(RAW_AUTHORITY_CODE, DESCRIPTION);
                this.errorMessage = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);

                ValidationRule<Authority> codeRule = mockAuthorityValidationRule().configReturnTrue(authority).build();
                ValidationRule<Authority>  accessibleResourceRule = mockAuthorityValidationRule().configReturnFalse(authority).validationError(errorMessage).build();

                this.policy = mockAuthorityValidationPolicy().codeRule(codeRule).accessibleResourceRule(accessibleResourceRule).build();
            }

            @Test
            @DisplayName("AuthorityInvalidException 이 발생해야 하며 예외 클래스에 에러 메시지가 포함되어야 한다.")
            void shouldThrowsAuthorityInvalidExceptionAndContainsErrorCodes() {
                AuthorityInvalidException exception = assertThrows(AuthorityInvalidException.class, () -> authority.validation(policy));

                assertTrue(exception.getErrors().contains(errorMessage));
            }
        }
    }
}