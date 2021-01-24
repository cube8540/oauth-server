package cube8540.oauth.authentication.credentials.resource.domain

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.ServiceInvalidException
import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.validator.core.ValidationError

class ResourceNotFoundException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun instance(description: String) = ResourceNotFoundException(ErrorCodes.NOT_FOUND, description)
    }
}

class ResourceRegisterException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun existsIdentifier(description: String) = ResourceRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description)
    }
}

class ResourceInvalidException(code: String, errors: Collection<ValidationError>): ServiceInvalidException(code, errors) {
    companion object {
        @JvmStatic
        fun instance(errors: List<ValidationError>) = ResourceInvalidException(ErrorCodes.INVALID_REQUEST, errors)
    }
}