package cube8540.oauth.authentication.resource.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import cube8540.validator.core.Validator;

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
    static SecuredResourceValidatorFactory makeErrorValidatorFactory(SecuredResource resource) {
        ValidationRule<SecuredResource> validationRule = mock(ValidationRule.class);
        SecuredResourceValidatorFactory factory = mock(SecuredResourceValidatorFactory.class);

        when(validationRule.isValid(resource)).thenReturn(false);
        when(validationRule.error()).thenReturn(new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE));

        Validator<SecuredResource> validator = Validator.of(resource)
                .registerRule(validationRule);
        when(factory.createValidator(resource)).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static SecuredResourceValidatorFactory makePassValidatorFactory(SecuredResource resource) {
        ValidationRule<SecuredResource> validationRule = mock(ValidationRule.class);
        SecuredResourceValidatorFactory factory = mock(SecuredResourceValidatorFactory.class);

        when(validationRule.isValid(resource)).thenReturn(true);

        Validator<SecuredResource> validator = Validator.of(resource)
                .registerRule(validationRule);
        when(factory.createValidator(resource)).thenReturn(validator);

        return factory;
    }
}
