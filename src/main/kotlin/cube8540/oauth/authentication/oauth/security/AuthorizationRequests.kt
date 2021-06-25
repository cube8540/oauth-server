package cube8540.oauth.authentication.oauth.security

import com.nimbusds.oauth2.sdk.pkce.CodeChallenge
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import cube8540.oauth.authentication.oauth.AuthorizationRequestKey
import cube8540.oauth.authentication.oauth.TokenRequestKey
import cube8540.oauth.authentication.oauth.extractScopes
import java.net.URI
import java.security.Principal
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType

interface AuthorizationRequest {
    val clientId: String?

    val username: String?

    val state: String?

    var redirectUri: URI?

    var requestScopes: Set<String>?

    val responseType: OAuth2AuthorizationResponseType?

    val codeChallenge: CodeChallenge?

    val codeChallengeMethod: CodeChallengeMethod?
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

    val codeVerifier: CodeVerifier?
}

data class DefaultAuthorizationRequest(
    override val clientId: String?,

    override val state: String?,

    override val username: String?,

    override var redirectUri: URI?,

    override var requestScopes: Set<String>?,

    override val responseType: OAuth2AuthorizationResponseType?,

    override val codeChallenge: CodeChallenge?,

    override val codeChallengeMethod: CodeChallengeMethod?
): AuthorizationRequest {

    constructor(requestMap: Map<String, String?>, principal: Principal?): this(
        clientId = requestMap[AuthorizationRequestKey.CLIENT_ID],
        state = requestMap[AuthorizationRequestKey.STATE],
        username = principal?.name,
        requestScopes = extractScopes(requestMap[AuthorizationRequestKey.SCOPE]),
        responseType = extractResponseType(requestMap[AuthorizationRequestKey.RESPONSE_TYPE]),
        redirectUri = requestMap[AuthorizationRequestKey.REDIRECT_URI]?.let { URI.create(it) },
        codeChallenge = requestMap[AuthorizationRequestKey.CODE_CHALLENGE]?.let { CodeChallenge.parse(it) },
        codeChallengeMethod = requestMap[AuthorizationRequestKey.CODE_CHALLENGE_METHOD]?.let { CodeChallengeMethod.parse(it) }
    )

    constructor(authorizationRequest: AuthorizationRequest): this(
        clientId = authorizationRequest.clientId,
        state = authorizationRequest.state,
        username = authorizationRequest.username,
        redirectUri = authorizationRequest.redirectUri,
        responseType = authorizationRequest.responseType,
        requestScopes = authorizationRequest.requestScopes?.let { HashSet(it) },
        codeChallenge = authorizationRequest.codeChallenge,
        codeChallengeMethod = authorizationRequest.codeChallengeMethod
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

    override val state: String?,

    override val codeVerifier: CodeVerifier?
): OAuth2TokenRequest {

    constructor(requestMap: Map<String, String?>): this(
        clientId = requestMap[TokenRequestKey.CLIENT_ID],
        code = requestMap[TokenRequestKey.CODE],
        username = requestMap[TokenRequestKey.USERNAME],
        password = requestMap[TokenRequestKey.PASSWORD],
        refreshToken = requestMap[TokenRequestKey.REFRESH_TOKEN],
        scopes = extractScopes(requestMap[TokenRequestKey.SCOPE]),
        state = requestMap[TokenRequestKey.STATE],
        grantType = requestMap[TokenRequestKey.GRANT_TYPE]?.let { AuthorizationGrantType(it) },
        redirectUri = requestMap[TokenRequestKey.REDIRECT_URI]?.let { URI(it) },
        codeVerifier = requestMap[TokenRequestKey.CODE_VERIFIER]?.let { CodeVerifier(it) }
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
