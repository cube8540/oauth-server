package cube8540.oauth.authentication.error.message

import java.io.Serializable

open class ErrorCodes internal constructor() {
    companion object {
        const val NOT_FOUND = "not_found"

        const val EXISTS_IDENTIFIER = "exists_identifier"

        const val INVALID_REQUEST = "invalid_request"

        const val ACCESS_DENIED = "access_denied"

        const val SERVER_ERROR = "server_error"
    }
}

class ErrorMessage<T>(val errorCode: String?, val description: T?): Serializable {
    companion object {
        @JvmField
        val ACCESS_DENIED_ERROR: ErrorMessage<Any> = ErrorMessage(ErrorCodes.ACCESS_DENIED, "access denied")

        @JvmField
        val UNKNOWN_SERVER_ERROR: ErrorMessage<Any> = ErrorMessage(ErrorCodes.SERVER_ERROR, "unknown server error")

        @JvmStatic
        fun <T> instance(errorCode: String?, description: T?): ErrorMessage<T> = ErrorMessage(errorCode, description)
    }
}