package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.net.URI;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorityTestHelper {

    static final String RAW_AUTHORITY_CODE = "AUTHORITY_CODE";
    static final OAuth2ScopeId AUTHORITY_CODE = new OAuth2ScopeId(RAW_AUTHORITY_CODE);
    static final String DESCRIPTION = "DESCRIPTION";

    static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    static final String ERROR_PROPERTY = "property";
    static final String ERROR_MESSAGE = "message";

    static final String RAW_RESOURCE = "/uri/**";
    static final URI RESOURCE = URI.create(RAW_RESOURCE);
    static final String RAW_CHANGE_RESOURCE = "/change/**";
    static final URI CHANGE_RESOURCE = URI.create(RAW_CHANGE_RESOURCE);

    static final ResourceMethod RESOURCE_METHOD = ResourceMethod.ALL;
    static final ResourceMethod CHANGE_RESOURCE_METHOD = ResourceMethod.POST;

    static MockValidationRule<SecuredResource> mockResourceValidationRule() {
        return new MockValidationRule<>();
    }

    static MockValidationRule<Authority> mockAuthorityValidationRule() {
        return new MockValidationRule<>();
    }

    static MockResourceValidationPolicy mockResourceValidationPolicy() {
        return new MockResourceValidationPolicy();
    }

    static MockAuthorityValidationPolicy mockAuthorityValidationPolicy() {
        return new MockAuthorityValidationPolicy();
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

    static final class MockAuthorityValidationPolicy {
        private AuthorityValidationPolicy policy;

        private MockAuthorityValidationPolicy() {
            this.policy = mock(AuthorityValidationPolicy.class);
        }

        MockAuthorityValidationPolicy codeRule(ValidationRule<Authority> rule) {
            when(policy.codeRule()).thenReturn(rule);
            return this;
        }

        MockAuthorityValidationPolicy accessibleResourceRule(ValidationRule<Authority> rule) {
            when(policy.accessibleResourceRule()).thenReturn(rule);
            return this;
        }

        AuthorityValidationPolicy build() {
            return policy;
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

        MockResourceValidationPolicy authoritiesRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.authoritiesRule()).thenReturn(validationRule);
            return this;
        }

        SecuredResourceValidationPolicy build() {
            return policy;
        }
    }
}
