package cube8540.oauth.authentication.oauth.error

open class OAuth2AccessTokenRegistrationException(message: String?, cause: Throwable?): RuntimeException(message, cause) {
    constructor(message: String): this(message, null)
}

open class OAuth2ClientRegistrationException(message: String?, cause: Throwable?): RuntimeException(message, cause) {
    constructor(message: String): this(message, null)
}