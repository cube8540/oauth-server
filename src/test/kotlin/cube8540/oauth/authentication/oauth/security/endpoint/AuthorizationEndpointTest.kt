package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.AuthorizationRequestKey
import cube8540.oauth.authentication.oauth.client.domain.ClientNotFoundException
import cube8540.oauth.authentication.oauth.error.*
import cube8540.oauth.authentication.oauth.security.*
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.approvalClientScopeDetails
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.approvalClientScopes
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.approvalRequestScopeDetails
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.approvalRequestScopes
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationErrorPage
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestClientId
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestPrincipalUsername
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestRedirectUri
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestScopes
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestScopesSet
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.authorizationRequestState
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.createAuthenticatedPrincipal
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.createAuthorizationRequestParameterMap
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.createNotAuthenticatedPrincipal
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.invalidGrantError
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.invalidRequestError
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.registeredClientId
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.registeredClientName
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.registeredClientScopes
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.registeredRedirectUri
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.resolvedApprovalScopes
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.resolvedRedirectUri
import cube8540.oauth.authentication.oauth.security.endpoint.AuthorizationTestEnvironment.unauthorizedClientError
import cube8540.oauth.authentication.security.AuthorityDetailsService
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.web.bind.support.SessionAttributeStore
import org.springframework.web.bind.support.SessionStatus
import org.springframework.web.context.request.ServletWebRequest
import org.springframework.web.servlet.ModelAndView
import org.springframework.web.servlet.view.RedirectView
import java.net.URI
import java.security.Principal
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class AuthorizationEndpointTest {

    private val clientDetailsService: OAuth2ClientDetailsService = mockk(relaxed = true)
    private val authorityDetailsService: AuthorityDetailsService = mockk(relaxed = true)
    private val responseEnhancer: AuthorizationResponseEnhancer = mockk(relaxed = true)
    private val autoApprovalScopeHandler: AutoApprovalScopeHandler = mockk(relaxed = true)

    private val requestValidator: OAuth2RequestValidator = mockk(relaxed = true)
    private val approvalResolver: ScopeApprovalResolver = mockk(relaxed = true)
    private val redirectResolver: RedirectResolver = mockk(relaxed = true)

    private val exceptionTranslator: OAuth2ExceptionTranslator = mockk(relaxed = true)

    private val sessionAttributeStore: SessionAttributeStore = mockk(relaxed = true)

    private val endpoint = AuthorizationEndpoint(clientDetailsService, authorityDetailsService, responseEnhancer, autoApprovalScopeHandler)

    init {
        endpoint.requestValidator = requestValidator
        endpoint.redirectResolver = redirectResolver
        endpoint.approvalResolver = approvalResolver
        endpoint.exceptionTranslator = exceptionTranslator
        endpoint.sessionAttributeStore = sessionAttributeStore
    }

    @Nested
    inner class AuthorizationTest {

        @Test
        fun `requested principal class type is not authentication`() {
            val principal: Principal = mockk()

            val thrown = catchThrowable { endpoint.authorize(HashMap(),  HashMap(), principal) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `requested is not authenticated`() {
            val principal = createNotAuthenticatedPrincipal(authorizationRequestPrincipalUsername)

            val thrown = catchThrowable { endpoint.authorize(HashMap(), HashMap(), principal) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `requested response type is null`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(responseType = null)
            val model: MutableMap<String, Any?> = HashMap()

            val thrown = catchThrowable { endpoint.authorize(parameter, model, principal) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `requested client id is null`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = null
            )
            val model: MutableMap<String, Any?> = HashMap()

            val thrown = catchThrowable { endpoint.authorize(parameter, model, principal) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `requested scope is not allowed`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                clientId = authorizationRequestClientId,
                responseType = OAuth2AuthorizationResponseType.CODE
            )
            val model: MutableMap<String, Any?> = HashMap()
            val clientDetails: OAuth2ClientDetails = mockk()

            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { requestValidator.validateScopes(clientDetails, authorizationRequestScopesSet) } returns false

            val thrown = catchThrowable { endpoint.authorize(parameter, model, principal) }
            assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
            assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
        }

        @Test
        fun `requested scope is null and some client scope is approval`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(
                scopes = null,
                clientId = authorizationRequestClientId,
                responseType = OAuth2AuthorizationResponseType.CODE,
                redirectUri = authorizationRequestRedirectUri
            )
            val model: MutableMap<String, Any?> = HashMap()
            val clientDetails: OAuth2ClientDetails = mockk {
                every { clientId } returns registeredClientId
                every { clientName } returns registeredClientName
                every { scopes } returns registeredClientScopes
            }

            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { requestValidator.validateScopes(clientDetails, emptySet()) } returns true
            every { autoApprovalScopeHandler.filterRequiredPermissionScopes(principal, clientDetails, registeredClientScopes) } returns approvalClientScopes
            every { authorityDetailsService.loadAuthorityByAuthorityCodes(approvalClientScopes) } returns approvalClientScopeDetails

            val result = endpoint.authorize(parameter, model, principal)
            val storedRequest = model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] as AuthorizationRequest
            assertThat(storedRequest.requestScopes).isEqualTo(registeredClientScopes)
            assertThat(model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME]).isEqualTo(registeredClientScopes.subtract(approvalClientScopes))
            assertThat(result.model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME]).isEqualTo(approvalClientScopeDetails)
        }

        @Test
        fun `requested scope is null and scope is all auto approval`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(
                scopes = null,
                clientId = authorizationRequestClientId,
                responseType = OAuth2AuthorizationResponseType.CODE,
                redirectUri = authorizationRequestRedirectUri
            )
            val model: MutableMap<String, Any?> = HashMap()
            val clientDetails: OAuth2ClientDetails = mockk {
                every { clientId } returns registeredClientId
                every { clientName } returns registeredClientName
                every { scopes } returns registeredClientScopes
            }

            val modelAndViewCaptor = slot<ModelAndView>()
            val authorizationRequestCaptor = slot<AuthorizationRequest>()

            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { requestValidator.validateScopes(clientDetails, emptySet()) } returns true
            every { autoApprovalScopeHandler.filterRequiredPermissionScopes(principal, clientDetails, registeredClientScopes) } returns emptySet()
            every { responseEnhancer.enhance(capture(modelAndViewCaptor), capture(authorizationRequestCaptor)) } returnsArgument 0

            val result = endpoint.authorize(parameter, model, principal)
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat((result.view as RedirectView).url).isEqualTo(resolvedRedirectUri.toString())
            assertThat(modelAndViewCaptor.captured).isEqualTo(result)
            assertThat(authorizationRequestCaptor.captured.requestScopes).isEqualTo(registeredClientScopes)
        }

        @Test
        fun `request scope is allowed`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val parameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val model: MutableMap<String, Any?> = HashMap()
            val clientDetails: OAuth2ClientDetails = mockk {
                every { clientId } returns registeredClientId
                every { clientName } returns registeredClientName
                every { scopes } returns registeredClientScopes
            }

            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { requestValidator.validateScopes(clientDetails, authorizationRequestScopesSet) } returns true
            every { autoApprovalScopeHandler.filterRequiredPermissionScopes(principal, clientDetails, authorizationRequestScopesSet) } returns approvalRequestScopes
            every { authorityDetailsService.loadAuthorityByAuthorityCodes(approvalRequestScopes) } returns approvalRequestScopeDetails

            val result = endpoint.authorize(parameter, model, principal)
            val storedRequest = model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] as AuthorizationRequest
            assertThat(storedRequest.requestScopes).isEqualTo(authorizationRequestScopesSet)
            assertThat(model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME]).isEqualTo(authorizationRequestScopesSet.subtract(approvalRequestScopes))
            assertThat(result.model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_SCOPES_NAME]).isEqualTo(approvalRequestScopeDetails)
        }

        @Test
        fun `request scope is all auto approval`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val modelAndViewCaptor = slot<ModelAndView>()
            val authorizationRequestCaptor = slot<AuthorizationRequest>()
            val parameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val model: MutableMap<String, Any?> = HashMap()
            val clientDetails: OAuth2ClientDetails = mockk {
                every { clientId } returns registeredClientId
                every { clientName } returns registeredClientName
                every { scopes } returns registeredClientScopes
            }

            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { requestValidator.validateScopes(clientDetails, authorizationRequestScopesSet) } returns true
            every { autoApprovalScopeHandler.filterRequiredPermissionScopes(principal, clientDetails, authorizationRequestScopesSet) } returns emptySet()
            every { responseEnhancer.enhance(capture(modelAndViewCaptor), capture(authorizationRequestCaptor)) } returnsArgument 0

            val result = endpoint.authorize(parameter, model, principal)
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat((result.view as RedirectView).url).isEqualTo(resolvedRedirectUri.toString())
            assertThat(modelAndViewCaptor.captured).isEqualTo(result)
            assertThat(authorizationRequestCaptor.captured.requestScopes).isEqualTo(authorizationRequestScopesSet)
        }
    }

    @Nested
    inner class ApprovalTest {

        @Test
        fun `requested principal class type is not authentication`() {
            val principal: Principal = mockk()
            val sessionStatus: SessionStatus = mockk(relaxed = true)

            val thrown = catchThrowable { endpoint.approval(HashMap(),  HashMap(), sessionStatus, principal) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
            verify { sessionStatus.setComplete() }
        }

        @Test
        fun `requested is not authenticated`() {
            val principal = createNotAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val sessionStatus: SessionStatus = mockk(relaxed = true)

            val thrown = catchThrowable { endpoint.approval(HashMap(),  HashMap(), sessionStatus, principal) }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
            verify { sessionStatus.setComplete() }
        }

        @Test
        fun `session not has original authorization request`() {
            val principal: Authentication = mockk {
                every { isAuthenticated } returns true
            }
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = null

            val thrown = catchThrowable { endpoint.approval(HashMap(), model, sessionStatus, principal) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
            verify { sessionStatus.setComplete() }
        }

        @Test
        fun `session not has authorization request`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val originalParameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = originalParameter
            model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] = null
            model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME] = emptySet<String>()

            val thrown = catchThrowable { endpoint.approval(HashMap(), model, sessionStatus, principal) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
            verify { sessionStatus.setComplete() }
        }

        @Test
        fun `auto approval scope is null`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val originalParameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val authorizationRequest: AuthorizationRequest = mockk()
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = originalParameter
            model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] = authorizationRequest
            model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME] = null

            val thrown = catchThrowable { endpoint.approval(HashMap(), model, sessionStatus, principal) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
            verify { sessionStatus.setComplete() }
        }

        @Test
        fun `auto approval scope is empty`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val originalParameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns registeredClientId
                every { redirectUri } returns registeredRedirectUri
            }
            val clientDetails: OAuth2ClientDetails = mockk()
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val approvalRequest: MutableMap<String, String?> = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            val modelAndViewCaptor = slot<ModelAndView>()
            val authorizationRequestCaptor = slot<AuthorizationRequest>()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = originalParameter
            model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] = authorizationRequest
            model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME] = emptySet<String>()
            every { approvalResolver.resolveApprovalScopes(authorizationRequest, approvalRequest) } returns resolvedApprovalScopes
            every { clientDetailsService.loadClientDetailsByClientId(registeredClientId) } returns clientDetails
            every { responseEnhancer.enhance(capture(modelAndViewCaptor), capture(authorizationRequestCaptor)) } returnsArgument 0

            val result = endpoint.approval(approvalRequest, model, sessionStatus, principal)
            verify { autoApprovalScopeHandler.storeAutoApprovalScopes(principal, clientDetails, resolvedApprovalScopes) }
            verify { sessionStatus.setComplete() }
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat(modelAndViewCaptor.captured).isEqualTo(result)
            assertThat(authorizationRequestCaptor.captured.clientId).isEqualTo(registeredClientId)
            assertThat(authorizationRequestCaptor.captured.requestScopes).isEqualTo(resolvedApprovalScopes)
        }

        @Test
        fun `auto approval is not empty`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val originalParameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = authorizationRequestRedirectUri
            )
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns registeredClientId
                every { redirectUri } returns registeredRedirectUri
            }
            val clientDetails: OAuth2ClientDetails = mockk()
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val approvalRequest: MutableMap<String, String?> = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            val modelAndViewCaptor = slot<ModelAndView>()
            val authorizationRequestCaptor = slot<AuthorizationRequest>()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = originalParameter
            model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] = authorizationRequest
            model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME] = approvalRequestScopes
            every { approvalResolver.resolveApprovalScopes(authorizationRequest, approvalRequest) } returns resolvedApprovalScopes
            every { clientDetailsService.loadClientDetailsByClientId(registeredClientId) } returns clientDetails
            every { responseEnhancer.enhance(capture(modelAndViewCaptor), capture(authorizationRequestCaptor)) } returnsArgument 0

            val result = endpoint.approval(approvalRequest, model, sessionStatus, principal)
            verify { autoApprovalScopeHandler.storeAutoApprovalScopes(principal, clientDetails, resolvedApprovalScopes.plus(approvalRequestScopes)) }
            verify { sessionStatus.setComplete() }
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat(modelAndViewCaptor.captured).isEqualTo(result)
            assertThat(authorizationRequestCaptor.captured.clientId).isEqualTo(registeredClientId)
            assertThat(authorizationRequestCaptor.captured.requestScopes).isEqualTo(resolvedApprovalScopes.plus(approvalRequestScopes))
        }

        @Test
        fun `stored redirect uri is null`() {
            val principal = createAuthenticatedPrincipal(authorizationRequestPrincipalUsername)
            val originalParameter = createAuthorizationRequestParameterMap(
                scopes = authorizationRequestScopes,
                responseType = OAuth2AuthorizationResponseType.CODE,
                clientId = authorizationRequestClientId,
                redirectUri = null
            )
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns registeredClientId
                every { redirectUri } returns registeredRedirectUri
            }
            val clientDetails: OAuth2ClientDetails = mockk()
            val sessionStatus: SessionStatus = mockk(relaxed = true)
            val approvalRequest: MutableMap<String, String?> = mockk(relaxed = true)
            val model: MutableMap<String, Any?> = HashMap()

            val modelAndViewCaptor = slot<ModelAndView>()
            val authorizationRequestCaptor = slot<AuthorizationRequest>()

            model[AuthorizationEndpoint.ORIGINAL_AUTHORIZATION_REQUEST_ATTRIBUTE] = originalParameter
            model[AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE] = authorizationRequest
            model[AuthorizationEndpoint.AUTHORIZATION_AUTO_APPROVAL_SCOPES_NAME] = approvalRequestScopes
            every { approvalResolver.resolveApprovalScopes(authorizationRequest, approvalRequest) } returns resolvedApprovalScopes
            every { clientDetailsService.loadClientDetailsByClientId(registeredClientId) } returns clientDetails
            every { responseEnhancer.enhance(capture(modelAndViewCaptor), capture(authorizationRequestCaptor)) } returnsArgument 0

            val result = endpoint.approval(approvalRequest, model, sessionStatus, principal)
            verify { autoApprovalScopeHandler.storeAutoApprovalScopes(principal, clientDetails, resolvedApprovalScopes.plus(approvalRequestScopes)) }
            verify { sessionStatus.setComplete() }
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat((result.view as RedirectView).url).isEqualTo(registeredRedirectUri.toString())
            assertThat(modelAndViewCaptor.captured).isEqualTo(result)
            assertThat(authorizationRequestCaptor.captured.redirectUri).isNull()
        }
    }

    @Nested
    inner class RedirectMismatchExceptionHandlingTest {

        @Test
        fun `handling redirect mismatch exception`() {
            val exception: RedirectMismatchException = mockk(relaxed = true)
            val servletResponse: HttpServletResponse = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk {
                every { response } returns servletResponse
            }

            endpoint.errorPage = authorizationErrorPage
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidGrantError, HttpStatus.UNAUTHORIZED)

            val result = endpoint.handleOAuth2AuthenticationException(exception, webRequest)
            verify { servletResponse.status = HttpStatus.UNAUTHORIZED.value() }
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(invalidGrantError)
        }
    }

    @Nested
    inner class ClientAuthenticationExceptionHandlingTest {

        @Test
        fun `client authentication exception handling`() {
            val exception: OAuth2ClientRegistrationException = mockk(relaxed = true)
            val servletResponse: HttpServletResponse = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk {
                every { response } returns servletResponse
            }

            endpoint.errorPage = authorizationErrorPage
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(unauthorizedClientError, HttpStatus.UNAUTHORIZED)

            val result = endpoint.handleClientRegistrationException(exception, webRequest)
            verify { servletResponse.status = HttpStatus.UNAUTHORIZED.value() }
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(unauthorizedClientError)
        }
    }

    @Nested
    inner class OtherExceptionHandlingTest {

        @Test
        fun `session not has authorization request and throws client registration exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val servletResponse: HttpServletResponse = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true) {
                every { getParameter(AuthorizationRequestKey.CLIENT_ID) } returns authorizationRequestClientId
                every { getParameter(AuthorizationRequestKey.REDIRECT_URI) } returns authorizationRequestRedirectUri
                every { response } returns servletResponse
            }

            endpoint.errorPage = authorizationErrorPage
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) }
                .throws(ClientNotFoundException(authorizationRequestClientId, authorizationRequestClientId))
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns null
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(invalidRequestError)
        }

        @Test
        fun `session has authorization request and throws client registration exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true)
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns authorizationRequestClientId
                every { redirectUri } returns URI.create(authorizationRequestRedirectUri)
            }

            endpoint.errorPage = authorizationErrorPage
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) }
                .throws(ClientNotFoundException(authorizationRequestClientId, authorizationRequestClientId))
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns authorizationRequest
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(invalidRequestError)
        }

        @Test
        fun `session not has authorization request and throws redirect mismatch exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val servletResponse: HttpServletResponse = mockk(relaxed = true)
            val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true) {
                every { getParameter(AuthorizationRequestKey.CLIENT_ID) } returns authorizationRequestClientId
                every { getParameter(AuthorizationRequestKey.REDIRECT_URI) } returns authorizationRequestRedirectUri
                every { response } returns servletResponse
            }

            endpoint.errorPage = authorizationErrorPage
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) }
                .throws(RedirectMismatchException(authorizationRequestRedirectUri))
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns null
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(invalidRequestError)
        }

        @Test
        fun `session has authorization request and throws redirect mismatch exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true)
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns authorizationRequestClientId
                every { redirectUri } returns URI.create(authorizationRequestRedirectUri)
            }

            endpoint.errorPage = authorizationErrorPage
            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) }
                .throws(RedirectMismatchException(authorizationRequestRedirectUri))
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns authorizationRequest
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.viewName).isEqualTo("forward:${authorizationErrorPage}")
            assertThat(result.model["error"]).isEqualTo(invalidRequestError)
        }

        @Test
        fun `session not has authorization request and not throws exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val servletResponse: HttpServletResponse = mockk(relaxed = true)
            val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true) {
                every { getParameter(AuthorizationRequestKey.CLIENT_ID) } returns authorizationRequestClientId
                every { getParameter(AuthorizationRequestKey.REDIRECT_URI) } returns authorizationRequestRedirectUri
                every { getParameter(AuthorizationRequestKey.STATE) } returns authorizationRequestState
                every { response } returns servletResponse
            }

            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns null
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat((result.view as RedirectView).url).isEqualTo(resolvedRedirectUri.toString())
            assertThat(result.model["error_code"]).isEqualTo(invalidRequestError.errorCode)
            assertThat(result.model["error_description"]).isEqualTo(invalidRequestError.description)
        }

        @Test
        fun `session has authorization request and not throws exception during exception handling`() {
            val exception: Exception = mockk(relaxed = true)
            val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk(relaxed = true)
            val authorizationRequest: AuthorizationRequest = mockk(relaxed = true) {
                every { clientId } returns authorizationRequestClientId
                every { redirectUri } returns URI.create(authorizationRequestRedirectUri)
            }

            every { clientDetailsService.loadClientDetailsByClientId(authorizationRequestClientId) } returns clientDetails
            every { redirectResolver.resolveRedirectURI(authorizationRequestRedirectUri, clientDetails) } returns resolvedRedirectUri
            every { sessionAttributeStore.retrieveAttribute(webRequest, AuthorizationEndpoint.AUTHORIZATION_REQUEST_ATTRIBUTE) } returns authorizationRequest
            every { exceptionTranslator.translate(exception) } returns ResponseEntity(invalidRequestError, HttpStatus.BAD_REQUEST)

            val result = endpoint.handleOtherException(exception, webRequest)
            assertThat(result.view).isInstanceOf(RedirectView::class.java)
            assertThat((result.view as RedirectView).url).isEqualTo(resolvedRedirectUri.toString())
            assertThat(result.model["error_code"]).isEqualTo(invalidRequestError.errorCode)
            assertThat(result.model["error_description"]).isEqualTo(invalidRequestError.description)
        }
    }
}