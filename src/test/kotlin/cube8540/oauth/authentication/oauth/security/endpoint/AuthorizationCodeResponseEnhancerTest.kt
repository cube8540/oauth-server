package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.AuthorizationResponseKey
import cube8540.oauth.authentication.oauth.security.AuthorizationCode
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import cube8540.oauth.authentication.oauth.security.OAuth2AuthorizationCodeGenerator
import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType
import org.springframework.web.servlet.ModelAndView

class AuthorizationCodeResponseEnhancerTest {

    private val generator: OAuth2AuthorizationCodeGenerator = mockk()

    private val enhancer = AuthorizationCodeResponseEnhancer(generator)

    @Test
    fun `response type not authorization code`() {
        val modelAndView: ModelAndView = mockk()
        val request: AuthorizationRequest = mockk {
            every { responseType } returns OAuth2AuthorizationResponseType.TOKEN
        }

        enhancer.nextEnhancer = null

        enhancer.enhance(modelAndView, request)
        verify { generator wasNot Called }
        verify { modelAndView wasNot Called }
    }

    @Test
    fun `response type is authorization code`() {
        val authorizationCode: AuthorizationCode = mockk {
            every { value } returns "authorizationCode"
        }
        val modelAndView: ModelAndView = mockk(relaxed = true)
        val request: AuthorizationRequest = mockk(relaxed = true) {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
        }

        enhancer.nextEnhancer = null
        every { generator.generateNewAuthorizationCode(request) } returns authorizationCode

        enhancer.enhance(modelAndView, request)
        verify { modelAndView.addObject(AuthorizationResponseKey.CODE, "authorizationCode") }
    }

    @Test
    fun `request not has state attribute`() {
        val authorizationCode: AuthorizationCode = mockk {
            every { value } returns "authorizationCode"
        }
        val modelAndView: ModelAndView = mockk(relaxed = true)
        val request: AuthorizationRequest = mockk(relaxed = true) {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
            every { state } returns null
        }

        enhancer.nextEnhancer = null
        every { generator.generateNewAuthorizationCode(request) } returns authorizationCode

        enhancer.enhance(modelAndView, request)
        verify { modelAndView.addObject(AuthorizationResponseKey.STATE, any()) wasNot Called }
    }

    @Test
    fun `request has state attribute`() {
        val authorizationCode: AuthorizationCode = mockk {
            every { value } returns "authorizationCode"
        }
        val modelAndView: ModelAndView = mockk(relaxed = true)
        val request: AuthorizationRequest = mockk(relaxed = true) {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
            every { state } returns "state"
        }

        enhancer.nextEnhancer = null
        every { generator.generateNewAuthorizationCode(request) } returns authorizationCode

        enhancer.enhance(modelAndView, request)
        verify { modelAndView.addObject(AuthorizationResponseKey.STATE, "state") }
    }

    @Test
    fun `not has next enhancer`() {
        val authorizationCode: AuthorizationCode = mockk {
            every { value } returns "authorizationCode"
        }
        val modelAndView: ModelAndView = mockk(relaxed = true)
        val request: AuthorizationRequest = mockk(relaxed = true) {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
            every { state } returns "state"
        }

        enhancer.nextEnhancer = null
        every { generator.generateNewAuthorizationCode(request) } returns authorizationCode

        val result = enhancer.enhance(modelAndView, request)
        assertThat(result).isEqualTo(modelAndView)
    }

    @Test
    fun `has next enhancer`() {
        val authorizationCode: AuthorizationCode = mockk {
            every { value } returns "authorizationCode"
        }
        val modelAndView: ModelAndView = mockk(relaxed = true)
        val request: AuthorizationRequest = mockk(relaxed = true) {
            every { responseType } returns OAuth2AuthorizationResponseType.CODE
            every { state } returns "state"
        }
        val nextModelAndView: ModelAndView = mockk()
        val nextEnhancer: AuthorizationResponseEnhancer = mockk {
            every { enhance(modelAndView, request) } returns nextModelAndView
        }

        enhancer.nextEnhancer = nextEnhancer
        every { generator.generateNewAuthorizationCode(request) } returns authorizationCode

        val result = enhancer.enhance(modelAndView, request)
        assertThat(result).isEqualTo(nextModelAndView)
    }

    @AfterEach
    fun clear() {
        clearAllMocks()
    }
}