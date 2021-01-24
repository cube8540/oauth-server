package cube8540.oauth.authentication.credentials.oauth.token.domain

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.message.ErrorCodes

class TokenAccessDeniedException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic fun denied(description: String) = TokenAccessDeniedException(ErrorCodes.ACCESS_DENIED, description)
    }
}

class TokenNotFoundException(code: String, description: String): ServiceException(code, description) {
    companion object {
        @JvmStatic fun instance(description: String) = TokenNotFoundException(ErrorCodes.NOT_FOUND, description)
    }
}