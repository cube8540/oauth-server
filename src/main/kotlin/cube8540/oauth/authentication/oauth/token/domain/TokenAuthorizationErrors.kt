package cube8540.oauth.authentication.oauth.token.domain

import cube8540.oauth.authentication.oauth.error.OAuth2AccessTokenRegistrationException

class OAuth2AccessTokenExpiredException(message: String?, cause: Throwable?): OAuth2AccessTokenRegistrationException(message, cause) {
    constructor(message: String?): this(message, null)
}

class OAuth2AccessTokenNotFoundException(accessToken: String?, cause: Throwable?): OAuth2AccessTokenRegistrationException("$accessToken is not found", cause) {
    constructor(accessToken: String?): this(accessToken, null)
}