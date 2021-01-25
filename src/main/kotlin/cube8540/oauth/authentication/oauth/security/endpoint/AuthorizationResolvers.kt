package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException
import cube8540.oauth.authentication.oauth.error.UserDeniedAuthorizationException
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import java.net.URI
import java.util.*

interface RedirectResolver {
    fun resolveRedirectURI(redirectURI: String?, clientDetails: OAuth2ClientDetails): URI
}

interface ScopeApprovalResolver {
    fun resolveApprovalScopes(originalRequest: AuthorizationRequest, approvalParameters: Map<String, String?>): Set<String>
}

class DefaultRedirectResolver: RedirectResolver {

    override fun resolveRedirectURI(redirectURI: String?, clientDetails: OAuth2ClientDetails): URI {
        if (redirectURI == null && clientDetails.registeredRedirectUris?.size?:0 == 1) {
            return clientDetails.registeredRedirectUris!!.iterator().next()
        }
        if (redirectURI == null) {
            throw InvalidRequestException.invalidRequest("redirect uri is required")
        }
        val requestingURI = URI.create(redirectURI)
        if (clientDetails.registeredRedirectUris!!.contains(requestingURI)) {
            return requestingURI
        } else {
            throw RedirectMismatchException("$redirectURI is not registered")
        }
    }
}

class DefaultScopeApprovalResolver: ScopeApprovalResolver {

    override fun resolveApprovalScopes(originalRequest: AuthorizationRequest, approvalParameters: Map<String, String?>): Set<String> {
        val approvalScopes: MutableSet<String> = HashSet()
        originalRequest.requestScopes?.forEach {
            val approvalScope = approvalParameters[it]
            if ("true" == approvalScope?.toLowerCase()) {
                approvalScopes.add(it)
            }
        }
        if (approvalScopes.isEmpty()) {
            throw UserDeniedAuthorizationException("User denied access")
        }
        return Collections.unmodifiableSet(approvalScopes)
    }
}