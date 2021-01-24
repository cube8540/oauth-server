package cube8540.oauth.authentication.credentials.oauth.security.endpoint

import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.web.servlet.ModelAndView
import org.springframework.web.servlet.view.RedirectView
import java.net.URI

class AuthorizationImplicitResponseEnhancer(
    private val tokenGranter: OAuth2AccessTokenGranter,
    private val clientDetailsService: OAuth2ClientDetailsService,
    var nextEnhancer: AuthorizationResponseEnhancer?
): AuthorizationResponseEnhancer {

    constructor(tokenGranter: OAuth2AccessTokenGranter, clientDetailsService: OAuth2ClientDetailsService):
            this(tokenGranter, clientDetailsService, null)

    override fun setNext(handler: AuthorizationResponseEnhancer): AuthorizationResponseEnhancer =
        handler.also { this.nextEnhancer = handler }

    override fun enhance(modelAndView: ModelAndView, request: AuthorizationRequest): ModelAndView {
        if (request.responseType?.equals(OAuth2AuthorizationResponseType.TOKEN) == true) {
            val clientDetails = clientDetailsService.loadClientDetailsByClientId(request.clientId!!)
            val token = tokenGranter.grant(clientDetails, ImplicitTokenRequest(request))
            enhanceRedirectUrl(modelAndView, request, token)
        }

        return nextEnhancer?.enhance(modelAndView, request) ?: modelAndView
    }

    private fun enhanceRedirectUrl(modelAndView: ModelAndView, authorizationRequest: AuthorizationRequest, token: OAuth2AccessTokenDetails) {
        val view = modelAndView.view as RedirectView
        var redirectUrl = (view.url + "#access_token=" + token.tokenValue + "&token_type=" + token.tokenType
                + "&expires_in=" + token.expiresIn + "&scope=" + token.scopes?.joinToString(" "))
        if (authorizationRequest.state != null) {
            redirectUrl += "&state=" + authorizationRequest.state
        }
        view.url = redirectUrl
    }

    private inner class ImplicitTokenRequest(request: AuthorizationRequest): OAuth2TokenRequest {
        override val grantType: AuthorizationGrantType = AuthorizationGrantType.IMPLICIT
        override val username: String? = request.username
        override val password: String? = null
        override val clientId: String? = request.clientId
        override val refreshToken: String? = null
        override val code: String? = null
        override val state: String? = request.state
        override val redirectUri: URI? = request.redirectUri
        override val scopes: Set<String>? = request.requestScopes
    }
}