package cube8540.oauth.authentication.oauth.security.provider

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.HttpRequestMethodNotSupportedException
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ClientCredentialsEndpointFilterTest {

    private val filterPath = "/auth"
    private val manager: AuthenticationManager = mockk()

    private val filter = ClientCredentialsEndpointFilter(filterPath)

    init {
        filter.setAuthenticationManager(manager)
    }

    @Test
    fun `request authentication not using post method when only post set`() {
        val request: HttpServletRequest = mockk {
            every { method } returns HttpMethod.GET.toString()
        }
        val response: HttpServletResponse = mockk()

        filter.onlyPost = true

        val thrown = Assertions.catchThrowable { filter.attemptAuthentication(request, response) }
        Assertions.assertThat(thrown).isInstanceOf(HttpRequestMethodNotSupportedException::class.java)
    }

    @Test
    fun `request authentication when request client id is null`() {
        val request: HttpServletRequest = mockk(relaxed = true) {
            every { method } returns HttpMethod.POST.toString()
            every { getParameter("client_id") } returns null
        }
        val response: HttpServletResponse = mockk()

        val thrown = Assertions.catchThrowable { filter.attemptAuthentication(request, response) }
        Assertions.assertThat(thrown).isInstanceOf(BadCredentialsException::class.java)
    }

    @Test
    fun `request basic authentication`() {
        val basicAuthentication = "Basic ${Base64.getEncoder().encodeToString("clientId:clientPassword".toByteArray())}"
        val request: HttpServletRequest = mockk(relaxed = true) {
            every { method } returns HttpMethod.POST.toString()
            every { getHeader(HttpHeaders.AUTHORIZATION) } returns basicAuthentication
        }
        val response: HttpServletResponse = mockk()
        val authenticationResult: Authentication = mockk()

        val authenticationCaptor = slot<Authentication>()

        every { manager.authenticate(capture(authenticationCaptor)) } returns authenticationResult

        val result = filter.attemptAuthentication(request, response)
        Assertions.assertThat(authenticationCaptor.captured.principal).isEqualTo("clientId")
        Assertions.assertThat(authenticationCaptor.captured.credentials).isEqualTo("clientPassword")
        Assertions.assertThat(result).isEqualTo(authenticationResult)
    }

    @Test
    fun `authentication by parameter`() {
        val request: HttpServletRequest = mockk(relaxed = true) {
            every { method } returns HttpMethod.POST.toString()
            every { getParameter("client_id") } returns "clientId"
            every { getParameter("client_secret") } returns "clientPassword"
        }
        val response: HttpServletResponse = mockk()
        val authenticationResult: Authentication = mockk()

        val authenticationCaptor = slot<Authentication>()

        every { manager.authenticate(capture(authenticationCaptor)) } returns authenticationResult

        val result = filter.attemptAuthentication(request, response)
        Assertions.assertThat(authenticationCaptor.captured.principal).isEqualTo("clientId")
        Assertions.assertThat(authenticationCaptor.captured.credentials).isEqualTo("clientPassword")
        Assertions.assertThat(result).isEqualTo(authenticationResult)
    }

    @Test
    fun `request when already authenticated`() {
        val request: HttpServletRequest = mockk(relaxed = true) {
            every { method } returns HttpMethod.POST.toString()
            every { getParameter("client_id") } returns "clientId"
            every { getParameter("client_secret") } returns "clientPassword"
        }
        val response: HttpServletResponse = mockk(relaxed = true)
        val authentication: Authentication = mockk(relaxed = true) {
            every { isAuthenticated } returns true
        }

        SecurityContextHolder.getContext().authentication = authentication

        val result = filter.attemptAuthentication(request, response)
        Assertions.assertThat(result).isEqualTo(authentication)
    }

    @AfterEach
    fun clear() {
        SecurityContextHolder.clearContext()
    }
}