package cube8540.oauth.authentication.credentials.oauth.error

import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

private const val UNAUTHORIZED = 401
private const val BAD_REQUEST = 400
private const val FORBIDDEN = 403

open class AbstractOAuth2AuthenticationException(val statusCode: Int, val error: OAuth2Error): AuthenticationException(error.description) {

    override fun toString(): String {
        val builder = StringBuilder("error=\"${error.errorCode}\"")
        val delimiter = ", "

        val errorMessage = error.description
        errorMessage?.let { msg -> builder.append(delimiter).append("error_description=\"").append(msg).append("\"") }

        return builder.toString()
    }
}

open class InvalidClientException protected constructor(code: String, message: String):
    AbstractOAuth2AuthenticationException(UNAUTHORIZED, OAuth2Error(code, message, null)) {

    companion object {
        @JvmStatic
        fun invalidClient(message: String): InvalidClientException =
            InvalidClientException(OAuth2ErrorCodes.INVALID_CLIENT, message)

        @JvmStatic
        fun unauthorizedClient(message: String): InvalidClientException =
            InvalidClientException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, message)
    }
}

open class InvalidGrantException protected constructor(code: String, message: String):
    AbstractOAuth2AuthenticationException(BAD_REQUEST, OAuth2Error(code, message, null)) {

    companion object {
        @JvmStatic
        fun invalidGrant(message: String) =
            InvalidGrantException(OAuth2ErrorCodes.INVALID_GRANT, message)

        @JvmStatic
        fun invalidScope(message: String) =
            InvalidGrantException(OAuth2ErrorCodes.INVALID_SCOPE, message)

        @JvmStatic
        fun unsupportedGrantType(message: String) =
            InvalidGrantException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, message)
    }
}

open class InvalidRequestException protected constructor(code: String, message: String):
    AbstractOAuth2AuthenticationException(BAD_REQUEST, OAuth2Error(code, message, null)) {

    companion object {
        @JvmStatic
        fun invalidRequest(message: String) =
            InvalidRequestException(OAuth2ErrorCodes.INVALID_REQUEST, message)

        @JvmStatic
        fun unsupportedResponseType(message: String) =
            InvalidRequestException(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, message)
    }
}

open class UserDeniedAuthorizationException(message: String?):
    AbstractOAuth2AuthenticationException(FORBIDDEN, OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, message, null))

open class RedirectMismatchException(message: String):
    InvalidGrantException(OAuth2ErrorCodes.INVALID_GRANT, message)