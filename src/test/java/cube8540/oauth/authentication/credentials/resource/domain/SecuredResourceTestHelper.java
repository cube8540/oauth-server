package cube8540.oauth.authentication.credentials.resource.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.net.URI;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecuredResourceTestHelper {

    static final String RAW_AUTHORITY_CODE = "AUTHORITY_CODE";
    static final AccessibleAuthority ACCESSIBLE_AUTHORITY = new AccessibleAuthority(RAW_AUTHORITY_CODE);

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

    @SuppressWarnings("unchecked")
    static ValidationRule<SecuredResource> makePassValidation(SecuredResource resource) {
        ValidationRule<SecuredResource> validation = mock(ValidationRule.class);

        when(validation.isValid(resource)).thenReturn(true);

        return validation;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<SecuredResource> makeErrorValidation(SecuredResource resource, ValidationError error) {
        ValidationRule<SecuredResource> validation = mock(ValidationRule.class);

        when(validation.isValid(resource)).thenReturn(false);
        when(validation.error()).thenReturn(error);

        return validation;
    }

    static MockResourceValidationPolicy makeResourceValidationPolicy() {
        return new MockResourceValidationPolicy();
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

        MockResourceValidationPolicy scopeAuthoritiesRule(ValidationRule<SecuredResource> validationRule) {
            when(this.policy.scopeAuthoritiesRule()).thenReturn(validationRule);
            return this;
        }

        SecuredResourceValidationPolicy build() {
            return policy;
        }
    }
}
