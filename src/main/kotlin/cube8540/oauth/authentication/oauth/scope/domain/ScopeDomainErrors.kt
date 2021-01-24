package cube8540.oauth.authentication.oauth.scope.domain

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.ServiceInvalidException
import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.validator.core.ValidationError

class ScopeInvalidException(code: String, errors: Collection<ValidationError>): ServiceInvalidException(code, errors) {
    companion object {
        @JvmStatic
        fun instance(errors: List<ValidationError>): ScopeInvalidException =
            ScopeInvalidException(ErrorCodes.INVALID_REQUEST, errors)
    }
}

class ScopeNotFoundException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun instance(description: String) = ScopeNotFoundException(ErrorCodes.NOT_FOUND, description)
    }
}

class ScopeRegisterException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun existsIdentifier(description: String) = ScopeRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description)
    }
}