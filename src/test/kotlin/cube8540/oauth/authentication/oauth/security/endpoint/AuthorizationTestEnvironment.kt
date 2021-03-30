package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.AuthorizationRequestKey
import cube8540.oauth.authentication.security.AuthorityDetails
import io.mockk.every
import io.mockk.mockk
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import java.net.URI

object AuthorizationTestEnvironment {

    internal const val authorizationErrorPage: String = "errorPage"

    internal const val authorizationRequestPrincipalUsername: String = "principalUsername"
    internal const val authorizationRequestClientId: String = "authorizationRequestClientId"
    internal const val authorizationRequestState: String = "authorizationRequestState"
    internal val authorizationRequestScopesSet: Set<String> = setOf("request-scope-1", "request-scope-2", "request-scope-3")
    internal const val authorizationRequestScopes: String = "request-scope-1 request-scope-2 request-scope-3"
    internal const val authorizationRequestRedirectUri: String = "http://localhost/callback"

    internal val approvalRequestScopes: Set<String> = setOf("request-scope-1", "request-scope-2")
    internal val approvalRequestScopeDetails: Set<AuthorityDetails> = setOf(
        mockk { every { code } returns "request-scope-1" },
        mockk { every { code } returns "request-scope-2" }
    )

    internal const val registeredClientId: String = "registeredClientId"
    internal const val registeredClientName: String = "registeredClientName"
    internal val registeredRedirectUri: URI = URI.create("http://localhost/registered")
    internal val registeredClientScopes: Set<String> = setOf("client-scope-1", "client-scope-2", "client-scope-3")

    internal val approvalClientScopes: Set<String> = setOf("client-scope-1", "client-scope-2")
    internal val approvalClientScopeDetails: Set<AuthorityDetails> = setOf(
        mockk { every { code } returns "client-scope-1" },
        mockk { every { code } returns "client-scope-2" }
    )

    internal val resolvedApprovalScopes: Set<String> = setOf("resolved-scope-1", "resolved-scope-2", "resolved-scope-3")

    internal val resolvedRedirectUri: URI = URI.create("http://localhost/resolved")

    internal val invalidRequestError = OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST)
    internal val unauthorizedClientError = OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
    internal val invalidGrantError = OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)

    fun createAuthorizationRequestParameterMap(
        clientId: String? = null,
        state: String? = null,
        redirectUri: String? = null,
        scopes: String? = null,
        responseType: OAuth2AuthorizationResponseType? = null,
        codeChallenge: String? = null,
        codeChallengeMethod: String? = null
    ): Map<String, String?> {
        val map: MutableMap<String, String?> = HashMap()

        map[AuthorizationRequestKey.CLIENT_ID] = clientId
        map[AuthorizationRequestKey.STATE] = state
        map[AuthorizationRequestKey.REDIRECT_URI] = redirectUri
        map[AuthorizationRequestKey.SCOPE] = scopes
        map[AuthorizationRequestKey.RESPONSE_TYPE] = responseType?.value
        map[AuthorizationRequestKey.CODE_CHALLENGE] = codeChallenge
        map[AuthorizationRequestKey.CODE_CHALLENGE_METHOD] = codeChallengeMethod

        return map
    }

    fun createNotAuthenticatedPrincipal(principalUsername: String): Authentication = mockk {
        every { name } returns principalUsername
        every { isAuthenticated } returns false
    }

    fun createAuthenticatedPrincipal(principalUsername: String): Authentication = mockk {
        every { name } returns principalUsername
        every { isAuthenticated } returns true
    }

    fun createAuthorizationRequest() {

    }
}