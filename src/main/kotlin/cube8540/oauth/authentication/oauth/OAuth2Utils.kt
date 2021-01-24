package cube8540.oauth.authentication.oauth

import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.util.*

class TokenRequestKey private constructor() {
    companion object {
        const val GRANT_TYPE = "grant_type"

        const val USERNAME = "username"

        const val PASSWORD = "password"

        const val CLIENT_ID = "client_id"

        const val REFRESH_TOKEN = "refresh_token"

        const val CODE = "code"

        const val STATE = "state"

        const val REDIRECT_URI = "redirect_uri"

        const val SCOPE = "scope"
    }
}

class AuthorizationRequestKey private constructor() {
    companion object {
        const val CLIENT_ID = "client_id"

        const val STATE = "state"

        const val REDIRECT_URI = "redirect_uri"

        const val SCOPE = "scope"

        const val RESPONSE_TYPE = "response_type"
    }
}

class AuthorizationResponseKey private constructor() {
    companion object {
        const val CODE = "code"

        const val STATE = "state"
    }
}

class AccessTokenSerializeKey private constructor() {
    companion object {
        const val ACCESS_TOKEN = "access_token"

        const val TOKEN_TYPE = "token_type"

        const val EXPIRES_IN = "expires_in"

        const val REFRESH_TOKEN = "refresh_token"

        const val SCOPE = "scope"
    }
}

class AccessTokenIntrospectionKey private constructor() {
    companion object {
        const val ACTIVE = "active"

        const val SCOPE = "scope"

        const val CLIENT_ID = "client_id"

        const val USERNAME = "username"

        const val EXPIRATION = "exp"
    }
}

class ErrorMessageKey private constructor() {
    companion object {
        const val ERROR = "error"

        const val DESCRIPTION = "error_description"
    }
}

fun extractScopes(value: String?): Set<String> {
    val result = HashSet<String>()
    if (value != null && value.trim().isNotEmpty()) {
        val scopes = value.split(Regex("[\\s+]"))
        result.addAll(scopes)
    }
    return result
}

fun extractGrantType(value: String): AuthorizationGrantType = when(value.toLowerCase()) {
    AuthorizationGrantType.AUTHORIZATION_CODE.value -> {
        AuthorizationGrantType.AUTHORIZATION_CODE
    }
    AuthorizationGrantType.PASSWORD.value -> {
        AuthorizationGrantType.PASSWORD
    }
    AuthorizationGrantType.CLIENT_CREDENTIALS.value -> {
        AuthorizationGrantType.CLIENT_CREDENTIALS
    }
    AuthorizationGrantType.REFRESH_TOKEN.value -> {
        AuthorizationGrantType.REFRESH_TOKEN
    }
    AuthorizationGrantType.IMPLICIT.value -> {
        AuthorizationGrantType.IMPLICIT
    }
    else -> {
        throw IllegalArgumentException("Unknown authorization grant type")
    }
}