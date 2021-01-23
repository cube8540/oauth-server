package cube8540.oauth.authentication.credentials.oauth.client.domain

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.ServiceInvalidException
import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.validator.core.ValidationError

class ClientErrorCodes: ErrorCodes() {
    companion object {
        const val INVALID_PASSWORD = "invalid_password"
    }
}

class ClientInvalidException(code: String, errors: Collection<ValidationError>): ServiceInvalidException(code, errors) {
    companion object {
        @JvmStatic fun instance(errors: List<ValidationError>) = ClientInvalidException(ErrorCodes.INVALID_REQUEST, errors)
    }
}

class ClientRegisterException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic fun existsIdentifier(description: String) = ClientRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description)
    }
}

class ClientNotFoundException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic fun instance(description: String) = ClientNotFoundException(ErrorCodes.NOT_FOUND, description)
    }
}

class ClientAuthorizationException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic fun invalidPassword(description: String) = ClientAuthorizationException(ClientErrorCodes.INVALID_PASSWORD, description)
    }
}