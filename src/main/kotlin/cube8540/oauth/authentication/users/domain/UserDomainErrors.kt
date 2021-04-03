package cube8540.oauth.authentication.users.domain

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.ServiceInvalidException
import cube8540.oauth.authentication.error.message.ErrorCodes
import io.github.cube8540.validator.core.ValidationError

open class UserErrorCodes: ErrorCodes() {
    companion object {
        const val INVALID_PASSWORD = "invalid_password"

        const val INVALID_KEY = "invalid_key"

        const val KEY_EXPIRED = "key_expired"

        const val ALREADY_CREDENTIALS = "already_credentials"
    }
}

class UserAuthorizationException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun invalidPassword(description: String): UserAuthorizationException =
            UserAuthorizationException(UserErrorCodes.INVALID_PASSWORD, description)

        @JvmStatic
        fun keyExpired(description: String): UserAuthorizationException =
            UserAuthorizationException(UserErrorCodes.KEY_EXPIRED, description)

        @JvmStatic
        fun invalidKey(description: String): UserAuthorizationException =
            UserAuthorizationException(UserErrorCodes.INVALID_KEY, description)

        @JvmStatic
        fun alreadyCredentials(description: String): UserAuthorizationException =
            UserAuthorizationException(UserErrorCodes.ALREADY_CREDENTIALS, description)
    }
}

class UserNotFoundException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun instance(description: String) = UserNotFoundException(ErrorCodes.NOT_FOUND, description)
    }
}

class UserInvalidException(code: String, errors: List<ValidationError>): ServiceInvalidException(code, errors) {
    companion object {
        @JvmStatic
        fun instance(errors: List<ValidationError>): UserInvalidException =
            UserInvalidException(ErrorCodes.INVALID_REQUEST, errors)
    }
}

class UserRegisterException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic
        fun existsIdentifier(description: String) = UserRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description)
    }
}