package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.security.*
import io.mockk.*
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.web.servlet.ModelAndView
import org.springframework.web.servlet.view.RedirectView
import java.net.URI

class AuthorizationImplicitResponseEnhancerTest {

    private val granter: OAuth2AccessTokenGranter = mockk()
    private val clientDetailsService: OAuth2ClientDetailsService = mockk()

    private val enhancer = AuthorizationImplicitResponseEnhancer(granter, clientDetailsService)

    @Test
    fun `response type not token`() {
        val modelAndView: ModelAndView = mockk()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
        }

        enhancer.nextEnhancer = null

        enhancer.enhance(modelAndView, request)
        verify { granter wasNot Called }
        verify { modelAndView wasNot Called }
    }

    @Test
    fun `request response type is token and request not has state attribute`() {
        val clientCaptor = slot<OAuth2ClientDetails>()
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.TOKEN
            every { state } returns null
            every { clientId } returns "clientId"
            every { username } returns "username"
            every { requestScopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { redirectUri } returns URI.create("http://localhost/callback")
        }
        val redirectViewer = RedirectView("http://localhost/callback")
        val modelAndView: ModelAndView = mockk {
            every { view } returns redirectViewer
        }
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "access-token"
            every { tokenType } returns "token-type"
            every { expiresIn } returns 10
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        enhancer.nextEnhancer = null
        every { clientDetailsService.loadClientDetailsByClientId("clientId") } returns clientDetails
        every { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) } returns accessToken

        enhancer.enhance(modelAndView, request)
        val expectedUrl = "http://localhost/callback#access_token=access-token&token_type=token-type&expires_in=10&scope=scope-1 scope-2 scope-3"
        verify { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) }
        assertThat(clientCaptor.captured).isEqualTo(clientDetails)
        assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
        assertThat(tokenRequestCaptor.captured.grantType).isEqualTo(AuthorizationGrantType.IMPLICIT)
        assertThat(tokenRequestCaptor.captured.scopes).isEqualTo(setOf("request-scope-1", "request-scope-2", "request-scope-3"))
        assertThat(redirectViewer.url).isEqualTo(expectedUrl)
    }

    @Test
    fun `request response type is token and request has state attribute`() {
        val clientCaptor = slot<OAuth2ClientDetails>()
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.TOKEN
            every { state } returns "state"
            every { clientId } returns "clientId"
            every { username } returns "username"
            every { requestScopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { redirectUri } returns URI.create("http://localhost/callback")
        }
        val redirectViewer = RedirectView("http://localhost/callback")
        val modelAndView: ModelAndView = mockk {
            every { view } returns redirectViewer
        }
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "access-token"
            every { tokenType } returns "token-type"
            every { expiresIn } returns 10
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        enhancer.nextEnhancer = null
        every { clientDetailsService.loadClientDetailsByClientId("clientId") } returns clientDetails
        every { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) } returns accessToken

        enhancer.enhance(modelAndView, request)
        val expectedUrl = "http://localhost/callback#access_token=access-token&token_type=token-type&expires_in=10&scope=scope-1 scope-2 scope-3&state=state"
        verify { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) }
        assertThat(clientCaptor.captured).isEqualTo(clientDetails)
        assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
        assertThat(tokenRequestCaptor.captured.grantType).isEqualTo(AuthorizationGrantType.IMPLICIT)
        assertThat(tokenRequestCaptor.captured.scopes).isEqualTo(setOf("request-scope-1", "request-scope-2", "request-scope-3"))
        assertThat(redirectViewer.url).isEqualTo(expectedUrl)
    }

    @Test
    fun `not has next enhancer`() {
        val clientCaptor = slot<OAuth2ClientDetails>()
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.TOKEN
            every { state } returns "state"
            every { clientId } returns "clientId"
            every { username } returns "username"
            every { requestScopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { redirectUri } returns URI.create("http://localhost/callback")
        }
        val redirectViewer = RedirectView("http://localhost/callback")
        val modelAndView: ModelAndView = mockk {
            every { view } returns redirectViewer
        }
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "access-token"
            every { tokenType } returns "token-type"
            every { expiresIn } returns 10
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        enhancer.nextEnhancer = null
        every { clientDetailsService.loadClientDetailsByClientId("clientId") } returns clientDetails
        every { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) } returns accessToken

        val result = enhancer.enhance(modelAndView, request)
        assertThat(result).isEqualTo(modelAndView)
    }

    @Test
    fun `has next enhancer`() {
        val clientCaptor = slot<OAuth2ClientDetails>()
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.TOKEN
            every { state } returns "state"
            every { clientId } returns "clientId"
            every { username } returns "username"
            every { requestScopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { redirectUri } returns URI.create("http://localhost/callback")
        }
        val redirectViewer = RedirectView("http://localhost/callback")
        val modelAndView: ModelAndView = mockk {
            every { view } returns redirectViewer
        }
        val nextModelAndView: ModelAndView = mockk()
        val nextEnhancer: AuthorizationResponseEnhancer = mockk {
            every { enhance(modelAndView, request) } returns nextModelAndView
        }
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "access-token"
            every { tokenType } returns "token-type"
            every { expiresIn } returns 10
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        enhancer.nextEnhancer = nextEnhancer
        every { clientDetailsService.loadClientDetailsByClientId("clientId") } returns clientDetails
        every { granter.grant(capture(clientCaptor), capture(tokenRequestCaptor)) } returns accessToken

        val result = enhancer.enhance(modelAndView, request)
        assertThat(result).isEqualTo(nextModelAndView)
    }

    @AfterEach
    fun clear() {
        clearAllMocks()
    }
}