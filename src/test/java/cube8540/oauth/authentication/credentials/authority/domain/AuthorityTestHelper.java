package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorityTestHelper {

    static MockValidationRule<SecuredResource> mockResourceValidationRule() {
        return new MockValidationRule<>();
    }

    static MockResourceValidationPolicy mockResourceValidationPolicy() {
        return new MockResourceValidationPolicy();
    }

    static final class MockValidationRule<T> {
        private ValidationRule<T> rule;

        @SuppressWarnings("unchecked")
        private MockValidationRule() {
            this.rule = mock(ValidationRule.class);
        }

        MockValidationRule<T> configReturnTrue(T target) {
            when(this.rule.isValid(target)).thenReturn(true);
            return this;
        }

        MockValidationRule<T> configReturnFalse(T target) {
            when(this.rule.isValid(target)).thenReturn(false);
            return this;
        }

        MockValidationRule<T> validationError(ValidationError error) {
            when(this.rule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return rule;
        }
    }

    static final class MockResourceValidationPolicy {
        private SecuredResourceValidationPolicy policy;

        private MockResourceValidationPolicy() {
            this.policy = mock(SecuredResourceValidationPolicy.class);
        }

        MockResourceValidationPolicy resourceIdRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.resourceIdRule()).thenReturn(validationRule);
            return this;
        }

        MockResourceValidationPolicy resourceRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.resourceRule()).thenReturn(validationRule);
            return this;
        }

        MockResourceValidationPolicy methodRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.methodRule()).thenReturn(validationRule);
            return this;
        }

        SecuredResourceValidationPolicy build() {
            return policy;
        }
    }
}
