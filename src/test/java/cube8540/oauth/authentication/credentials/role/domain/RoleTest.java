package cube8540.oauth.authentication.credentials.role.domain;

import cube8540.oauth.authentication.credentials.role.domain.exception.RoleInvalidException;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.role.domain.RoleTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.role.domain.RoleTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.role.domain.RoleTestHelper.mocKValidationRule;
import static cube8540.oauth.authentication.credentials.role.domain.RoleTestHelper.mockValidationPolicy;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("권한 도메인 테스트")
class RoleTest {

    @Nested
    @DisplayName("권한 유효성 체크")
    class RoleValidation {

        @Nested
        @DisplayName("권한 코드가 유효하지 않을시")
        class WhenAuthorityCodeIsNotAllowed {
            private Role role;
            private RoleValidationPolicy policy;
            private ValidationError error;

            @BeforeEach
            void setup() {
                this.role = new Role(RAW_AUTHORITY_CODE, DESCRIPTION);
                this.error = new ValidationError("code", "invalid code");

                ValidationRule<Role> roleCodeRule = mocKValidationRule().configValidationFalse().error(error).build();

                this.policy = mockValidationPolicy().roleCodeRule(roleCodeRule).build();
            }

            @Test
            @DisplayName("RoleInvalidException이 발생해야 한다.")
            void shouldThrowRoleInvalidException() {
                assertThrows(RoleInvalidException.class, () -> role.validate(policy));
            }

            @Test
            @DisplayName("권한 코드 유효성에 관련된 어리가 포함 되어야 한다.")
            void shouldContainsAuthorityCodeErrorMessage() {
                RoleInvalidException e = assertThrows(RoleInvalidException.class, () -> role.validate(policy));
                assertTrue(e.getErrors().contains(error));
            }
        }
    }
}