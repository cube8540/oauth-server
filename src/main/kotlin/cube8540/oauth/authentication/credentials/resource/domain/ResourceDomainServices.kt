package cube8540.oauth.authentication.credentials.resource.domain

import cube8540.validator.core.Validator

interface SecuredResourceValidatorFactory {
    fun createValidator(resource: SecuredResource): Validator<SecuredResource>
}