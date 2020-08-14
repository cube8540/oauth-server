package cube8540.oauth.authentication.credentials.resource.domain;

import cube8540.validator.core.Validator;

public interface SecuredResourceValidatorFactory {

    Validator<SecuredResource> createValidator(SecuredResource resource);

}
