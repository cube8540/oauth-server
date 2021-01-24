package cube8540.oauth.authentication.credentials.oauth.security

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequestKey
import cube8540.oauth.authentication.credentials.oauth.TokenRequestKey
import cube8540.oauth.authentication.credentials.oauth.extractScopes
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import java.net.URI
import java.security.Principal
import java.util.*

interface AuthorizationRequest {
    val clientId: String?

    val username: String?

    val state: String?

    var redirectUri: URI?

    var requestScopes: Set<String>?

    val responseType: OAuth2AuthorizationResponseType?
}

interface OAuth2TokenRequest {
    val grantType: AuthorizationGrantType?

    val username: String?

    val password: String?

    val clientId: String?

    val refreshToken: String?

    val code: String?

    val state: String?

    val redirectUri: URI?

    val scopes: Set<String>?
}

data class DefaultAuthorizationRequest(
    override val clientId: String?,

    override val state: String?,

    override val username: String?,

    override var redirectUri: URI?,

    override var requestScopes: Set<String>?,

    override val responseType: OAuth2AuthorizationResponseType?
): AuthorizationRequest {

    constructor(requestMap: Map<String, String?>, principal: Principal?): this(
        clientId = requestMap[AuthorizationRequestKey.CLIENT_ID],
        state = requestMap[AuthorizationRequestKey.STATE],
        username = principal?.name,
        requestScopes = extractScopes(requestMap[AuthorizationRequestKey.SCOPE]),
        responseType = extractResponseType(requestMap[AuthorizationRequestKey.RESPONSE_TYPE]),
        redirectUri = requestMap[AuthorizationRequestKey.REDIRECT_URI]?.let { uri -> URI.create(uri) }
    )

    constructor(authorizationRequest: AuthorizationRequest): this(
        clientId = authorizationRequest.clientId,
        state = authorizationRequest.state,
        username = authorizationRequest.username,
        redirectUri = authorizationRequest.redirectUri,
        responseType = authorizationRequest.responseType,
        requestScopes = authorizationRequest.requestScopes?.let { scopes -> HashSet(scopes) }
    )
}

data class DefaultOAuth2TokenRequest(
    override val clientId: String?,

    override val code: String?,

    override val grantType: AuthorizationGrantType?,

    override val username: String?,

    override val password: String?,

    override val redirectUri: URI?,

    override val refreshToken: String?,

    override val scopes: Set<String>?,

    override val state: String?
): OAuth2TokenRequest {

    constructor(requestMap: Map<String, String?>): this(
        clientId = requestMap[TokenRequestKey.CLIENT_ID],
        code = requestMap[TokenRequestKey.CODE],
        username = requestMap[TokenRequestKey.USERNAME],
        password = requestMap[TokenRequestKey.PASSWORD],
        refreshToken = requestMap[TokenRequestKey.REFRESH_TOKEN],
        scopes = extractScopes(requestMap[TokenRequestKey.SCOPE]),
        state = requestMap[TokenRequestKey.STATE],
        grantType = requestMap[TokenRequestKey.GRANT_TYPE]?.let { type -> AuthorizationGrantType(type) },
        redirectUri = requestMap[TokenRequestKey.REDIRECT_URI]?.let { uri -> URI(uri) },
    )
}

interface OAuth2RequestValidator {
    fun validateScopes(clientDetails: OAuth2ClientDetails, scopes: Set<String>?): Boolean

    fun validateScopes(approvalScopes: Set<String>, requestScopes: Set<String>?): Boolean
}

class DefaultOAuth2RequestValidator: OAuth2RequestValidator {
    override fun validateScopes(clientDetails: OAuth2ClientDetails, scopes: Set<String>?): Boolean =
        validateScopes(clientDetails.scopes, scopes)

    override fun validateScopes(approvalScopes: Set<String>, requestScopes: Set<String>?): Boolean =
        requestScopes == null || approvalScopes.containsAll(requestScopes)
}

private fun extractResponseType(responseType: String?) = when (responseType) {
    OAuth2AuthorizationResponseType.CODE.value -> OAuth2AuthorizationResponseType.CODE
    OAuth2AuthorizationResponseType.TOKEN.value -> OAuth2AuthorizationResponseType.TOKEN
    else -> null
}
