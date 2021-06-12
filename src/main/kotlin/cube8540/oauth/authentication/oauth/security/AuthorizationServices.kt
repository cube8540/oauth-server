package cube8540.oauth.authentication.oauth.security

import java.io.Serializable

data class AuthorizationCode(val value: String): Serializable

interface OAuth2AccessTokenGranter {
    fun grant(clientDetails: OAuth2ClientDetails, tokenRequest: OAuth2TokenRequest): OAuth2AccessTokenDetails
}

interface OAuth2TokenRevoker {
    fun revoke(tokenValue: String): OAuth2AccessTokenDetails
}

interface OAuth2AuthorizationCodeGenerator {
    fun generateNewAuthorizationCode(request: AuthorizationRequest): AuthorizationCode
}

interface OAuth2AccessTokenDetailsService {
    fun readAccessToken(tokenValue: String): OAuth2AccessTokenDetails
}

interface OAuth2ClientDetailsService {
    fun loadClientDetailsByClientId(clientId: String): OAuth2ClientDetails
}