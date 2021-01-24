package cube8540.oauth.authentication.credentials.oauth.token.domain

interface AuthorizationCodeGenerator {
    fun generate(): String
}

interface OAuth2ComposeUniqueKeyGenerator {
    fun generateKey(token: OAuth2AuthorizedAccessToken): OAuth2ComposeUniqueKey
}

interface OAuth2TokenEnhancer {
    fun enhance(accessToken: OAuth2AuthorizedAccessToken)
}

interface OAuth2TokenIdGenerator {
    fun generateTokenValue(): OAuth2TokenId
}