package cube8540.oauth.authentication.credentials.role.domain;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RoleTestHelper {

    static final String RAW_AUTHORITY_CODE = "AUTH-ID";
    static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_AUTHORITY_CODE);

    static final String DESCRIPTION = "DESCRIPTION";

    static MocKValidationRule<Role> mocKValidationRule() {
        return new MocKValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static class MockValidationPolicy {
        private RoleValidationPolicy policy;

        private MockValidationPolicy() {
            this.policy = mock(RoleValidationPolicy.class);
        }

        MockValidationPolicy roleCodeRule(ValidationRule<Role> roleCodeRule) {
            when(policy.roleCodeRule()).thenReturn(roleCodeRule);
            return this;
        }

        RoleValidationPolicy build() {
            return policy;
        }
    }

    static class MocKValidationRule<T> {
        private ValidationRule<T> validationRule;

        @SuppressWarnings("unchecked")
        private MocKValidationRule() {
            this.validationRule = mock(ValidationRule.class);
        }

        MocKValidationRule<T> configValidationTrue() {
            when(validationRule.isValid(any())).thenReturn(true);
            return this;
        }

        MocKValidationRule<T> configValidationFalse() {
            when(validationRule.isValid(any())).thenReturn(false);
            return this;
        }

        MocKValidationRule<T> error(ValidationError error) {
            when(validationRule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }
}
