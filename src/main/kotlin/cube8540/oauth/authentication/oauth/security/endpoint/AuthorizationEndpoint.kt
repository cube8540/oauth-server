package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.security.AuthorityDetailsService
import cube8540.oauth.authentication.oauth.AuthorizationRequestKey
import cube8540.oauth.authentication.oauth.error.AbstractOAuth2AuthenticationException
import cube8540.oauth.authentication.oauth.error.InvalidGrantException.Companion.invalidScope
import cube8540.oauth.authentication.oauth.error.InvalidRequestException.Companion.invalidRequest
import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.oauth.error.OAuth2ExceptionTranslator
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.DefaultAuthorizationRequest
import cube8540.oauth.authentication.oauth.security.DefaultOAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpoint.Companion.AUTHORIZATION_REQUEST_ATTRIBUTE
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationEndpoint.Companion.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE
import cube8540.oauth.authentication.error.ExceptionTranslator
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.SessionAttributes
import org.springframework.web.bind.support.DefaultSessionAttributeStore
import org.springframework.web.bind.support.SessionAttributeStore
import org.springframework.web.bind.support.SessionStatus
import org.springframework.web.context.request.ServletWebRequest
import org.springframework.web.servlet.ModelAndView
import org.springframework.web.servlet.view.RedirectView
import java.net.URI
import java.security.Principal
import java.util.*

@Controller
@SessionAttributes(value = [AUTHORIZATION_REQUEST_ATTRIBUTE, ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE])
class AuthorizationEndpoint @Autowired constructor(
    @Qualifier("defaultOAuth2ClientDetailsService")
    private val clientDetailsService: OAuth2ClientDetailsService,

    @Qualifier("defaultScopeDetailsService")
    private val scopeDetailsService: AuthorityDetailsService,

    private val responseEnhancer: AuthorizationResponseEnhancer
) {

    companion object {
        const val ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE = "originalAuthorizationRequest"
        const val AUTHORIZATION_REQUEST_ATTRIBUTE = "authorizationRequest"
        const val AUTHORIZATION_REQUEST_CLIENT_NAME = "authorizationRequestClientName"
        const val AUTHORIZATION_REQUEST_SCOPES_NAME = "authorizationRequestScopes"

        const val DEFAULT_FORWARD_PREFIX = "forward:"

        const val DEFAULT_ERROR_PAGE = "/oauth/error"
        const val DEFAULT_APPROVAL_PAGE = "$DEFAULT_FORWARD_PREFIX/oauth/approval"
    }

    private val logger = LoggerFactory.getLogger(this.javaClass)

    var sessionAttributeStore: SessionAttributeStore = DefaultSessionAttributeStore()
    var exceptionTranslator: ExceptionTranslator<OAuth2Error> = OAuth2ExceptionTranslator()
    var redirectResolver: RedirectResolver = DefaultRedirectResolver()
    var approvalResolver: ScopeApprovalResolver = DefaultScopeApprovalResolver()
    var requestValidator: OAuth2RequestValidator = DefaultOAuth2RequestValidator()

    var errorPage: String = DEFAULT_ERROR_PAGE
        set(value) {
            field = "$DEFAULT_FORWARD_PREFIX$value"
        }
    var approvalPage: String = DEFAULT_APPROVAL_PAGE
        set(value) {
            field = "$DEFAULT_FORWARD_PREFIX$value"
        }

    @GetMapping(value = ["/oauth/authorize"])
    fun authorize(@RequestParam parameters: Map<String, String?>, model: MutableMap<String, Any?>, principal: Principal): ModelAndView {
        if (principal !is Authentication || !principal.isAuthenticated) {
            throw InsufficientAuthenticationException("User must be authenticated")
        }

        val authorizationRequest = DefaultAuthorizationRequest(parameters, principal)
        if (authorizationRequest.responseType == null || authorizationRequest.clientId == null) {
            throw invalidRequest("Required parameter is missing")
        }

        val clientDetails = clientDetailsService.loadClientDetailsByClientId(authorizationRequest.clientId)
        val redirectUri = redirectResolver.resolveRedirectURI(parameters[AuthorizationRequestKey.REDIRECT_URI], clientDetails)
        authorizationRequest.redirectUri = redirectUri

        if (!requestValidator.validateScopes(clientDetails, authorizationRequest.requestScopes)) {
            throw invalidScope("cannot grant scope")
        }
        authorizationRequest.requestScopes = extractRequestScopes(clientDetails, authorizationRequest)

        model[AUTHORIZATION_REQUEST_ATTRIBUTE] = authorizationRequest
        model[ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = parameters

        val scopeDetails = scopeDetailsService.loadAuthorityByAuthorityCodes(authorizationRequest.requestScopes!!)
        return ModelAndView(approvalPage)
            .addObject(AUTHORIZATION_REQUEST_CLIENT_NAME, clientDetails.clientName)
            .addObject(AUTHORIZATION_REQUEST_SCOPES_NAME, scopeDetails)
    }

    @PostMapping(value = ["/oauth/authorize"])
    fun approval(@RequestParam approvalParameters: Map<String, String?>, model: MutableMap<String, Any?>, sessionStatus: SessionStatus, principal: Principal): ModelAndView {
        return try {
            if (principal !is Authentication || !principal.isAuthenticated) {
                throw InsufficientAuthenticationException("User must be authenticated")
            }

            val originalAuthorizationRequestMap: Map<*, *>? = (model[ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] as Map<*, *>?)
            val originalAuthorizationRequest: AuthorizationRequest? = (model[AUTHORIZATION_REQUEST_ATTRIBUTE] as AuthorizationRequest?)
            if (originalAuthorizationRequestMap == null || originalAuthorizationRequest == null) {
                throw invalidRequest("Cannot approval uninitialized authorization request")
            }

            val authorizationRequest = DefaultAuthorizationRequest(originalAuthorizationRequest)
            val approvalScopes = approvalResolver.resolveApprovalScopes(originalAuthorizationRequest, approvalParameters)
            authorizationRequest.requestScopes = approvalScopes

            val redirectUri = authorizationRequest.redirectUri!!
            if (originalAuthorizationRequestMap[AuthorizationRequestKey.REDIRECT_URI] == null) {
                authorizationRequest.redirectUri = null
            }

            responseEnhancer.enhance(ModelAndView(RedirectView(redirectUri.toString())), authorizationRequest)
        } finally {
            sessionStatus.setComplete()
        }
    }

    @ExceptionHandler(value = [OAuth2ClientRegistrationException::class])
    fun handleClientRegistrationException(e: OAuth2ClientRegistrationException, webRequest: ServletWebRequest): ModelAndView {
        logger.warn("Handling error client registration exception: {} {}", e.javaClass.name, e.message)
        return handleException(e, webRequest)
    }

    @ExceptionHandler(value = [AbstractOAuth2AuthenticationException::class])
    fun handleOAuth2AuthenticationException(e: AbstractOAuth2AuthenticationException, webRequest: ServletWebRequest): ModelAndView {
        logger.warn("Handling error {} {}", e.javaClass.name, e.message)
        return handleException(e, webRequest)
    }

    @ExceptionHandler(value = [Exception::class])
    fun handleOtherException(e: Exception, webRequest: ServletWebRequest): ModelAndView {
        logger.warn("Handling error {} {}", e.javaClass.name, e.message)
        return handleException(e, webRequest)
    }

    private fun handleException(e: Exception, webRequest: ServletWebRequest): ModelAndView {
        val responseEntity = exceptionTranslator.translate(e)
        webRequest.response!!.status = responseEntity.statusCode.value()

        if (e is OAuth2ClientRegistrationException || e is RedirectMismatchException) {
            return ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.body))
        }

        val authorizationRequest: AuthorizationRequest = getErrorAuthorizationRequest(webRequest)
        return try {
            val clientDetails = clientDetailsService.loadClientDetailsByClientId(authorizationRequest.clientId!!)
            val storedRedirectUri = authorizationRequest.redirectUri?.toString()
            val redirectUri = redirectResolver.resolveRedirectURI(storedRedirectUri, clientDetails)
            getUnsuccessfulRedirectView(redirectUri, responseEntity.body!!, authorizationRequest)
        } catch (exception: Exception) {
            logger.error("An exception occurred during error handling {} {}", exception.javaClass.name, exception.message)
            ModelAndView(errorPage, Collections.singletonMap("error", responseEntity.body))
        }
    }

    private fun getUnsuccessfulRedirectView(redirectUri: URI, error: OAuth2Error, authorizationRequest: AuthorizationRequest): ModelAndView {
        val modelAndView = ModelAndView(RedirectView(redirectUri.toString()))
            .addObject("error_code", error.errorCode)
            .addObject("error_description", error.description)

        if (authorizationRequest.state != null) {
            modelAndView.addObject("state", authorizationRequest.state)
        }
        return modelAndView
    }

    private fun getErrorAuthorizationRequest(webRequest: ServletWebRequest): AuthorizationRequest {
        val authorizationRequest: AuthorizationRequest? = sessionAttributeStore
            .retrieveAttribute(webRequest, AUTHORIZATION_REQUEST_ATTRIBUTE) as AuthorizationRequest?
        if (authorizationRequest != null) {
            return authorizationRequest
        }

        val parameters: MutableMap<String, String?> = HashMap()
        parameters[AuthorizationRequestKey.REDIRECT_URI] = webRequest.getParameter(AuthorizationRequestKey.REDIRECT_URI)
        parameters[AuthorizationRequestKey.CLIENT_ID] = webRequest.getParameter(AuthorizationRequestKey.CLIENT_ID)
        parameters[AuthorizationRequestKey.STATE] = webRequest.getParameter(AuthorizationRequestKey.STATE)
        return DefaultAuthorizationRequest(parameters, SecurityContextHolder.getContext().authentication)
    }

    protected fun extractRequestScopes(clientDetails: OAuth2ClientDetails, authorizationRequest: AuthorizationRequest): Set<String> {
        return if (authorizationRequest.requestScopes?.isNotEmpty() == true) {
            authorizationRequest.requestScopes!!
        } else {
            clientDetails.scopes
        }
    }

}