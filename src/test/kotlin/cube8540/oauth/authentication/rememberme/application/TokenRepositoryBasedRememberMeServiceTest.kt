package cube8540.oauth.authentication.rememberme.application

import cube8540.oauth.authentication.rememberme.domain.RememberMePrincipal
import cube8540.oauth.authentication.rememberme.domain.RememberMeToken
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenGenerator
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenRepository
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenSeries
import cube8540.oauth.authentication.rememberme.domain.RememberMeTokenValue
import io.mockk.InternalPlatformDsl.toStr
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import io.mockk.verifyOrder
import java.util.Base64
import java.util.Optional
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsChecker
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.rememberme.CookieTheftException

class TokenRepositoryBasedRememberMeServiceTest {

    private val rememberMeCookieName = "cookieName"
    private val requestRememberMeParameterName = "requestRememberMeParameterName"

    private val checker: UserDetailsChecker = mockk(relaxed = true)
    private val generator: RememberMeTokenGenerator = mockk(relaxed = true)
    private val repository: RememberMeTokenRepository = mockk(relaxed = true)
    private val userDetailsService: UserDetailsService = mockk(relaxed = true)

    private val service = TokenRepositoryBasedRememberMeService("key", generator, repository, userDetailsService)

    init {
        service.setCookieName(rememberMeCookieName)
        service.setUserDetailsChecker(checker)
        service.parameter = requestRememberMeParameterName
    }

    @Nested
    inner class OnLoginSuccessTest {

        @Test
        fun `save cookie by http servlet response`() {
            val cookieCaptor = slot<Cookie>()

            val authentication: Authentication = mockk(relaxed = true) {
                every { name } returns "username"
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { contextPath } returns "http://localhost:8080"
                every { getParameter(requestRememberMeParameterName) } returns "true"
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { generator.generateTokenSeries() } returns RememberMeTokenSeries("tokenSeries")
            every { generator.generateTokenValue() } returns RememberMeTokenValue("tokenValue")
            every { response.addCookie(capture(cookieCaptor)) } just Runs
            every { repository.save(any()) } returnsArgument 0

            service.loginSuccess(request, response, authentication)
            assertThat(cookieCaptor.isCaptured).isTrue
            assertThat(cookieCaptor.captured.name).isEqualTo(rememberMeCookieName)
            assertThat(cookieCaptor.captured.maxAge).isEqualTo(RememberMeToken.tokenValiditySeconds)
            assertThat(cookieCaptor.captured.path).isEqualTo("http://localhost:8080")
            assertThat(cookieCaptor.captured.value).isEqualTo(savedCookieValue("tokenSeries", "tokenValue"))
        }

        @Test
        fun `save remember me token by repository`() {
            val tokenCaptor = slot<RememberMeToken>()

            val authentication: Authentication = mockk(relaxed = true) {
                every { name } returns "username"
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { contextPath } returns "http://localhost:8080"
                every { getParameter(requestRememberMeParameterName) } returns "true"
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { generator.generateTokenSeries() } returns RememberMeTokenSeries("tokenSeries")
            every { generator.generateTokenValue() } returns RememberMeTokenValue("tokenValue")
            every { response.addCookie(any()) } just Runs
            every { repository.save(capture(tokenCaptor)) } returnsArgument 0

            service.loginSuccess(request, response, authentication)
            assertThat(tokenCaptor.isCaptured).isTrue
            assertThat(tokenCaptor.captured.series).isEqualTo(RememberMeTokenSeries("tokenSeries"))
            assertThat(tokenCaptor.captured.tokenValue).isEqualTo(RememberMeTokenValue("tokenValue"))
            assertThat(tokenCaptor.captured.username).isEqualTo(RememberMePrincipal("username"))
        }
    }

    @Nested
    inner class ProcessAutoLoginTest {

        @Test
        fun `cookie is not found in request`() {
            val emptyCookieRequest: HttpServletRequest = mockk(relaxed = true)
            val response: HttpServletResponse = mockk(relaxed = true)

            val result = service.autoLogin(emptyCookieRequest, response)
            assertThat(result).isNull()
        }

        @Test
        fun `cookie is not base64 encoding character`() {
            val cancelCookieCaptor = slot<Cookie>()

            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns "invalid cookie"
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { response.addCookie(capture(cancelCookieCaptor)) } just Runs

            service.autoLogin(request, response)
            assertThat(cancelCookieCaptor.isCaptured).isTrue
            assertCancelCookie(cancelCookieCaptor.captured)
        }

        @Test
        fun `cookie is invalid`() {
            val cancelCookieCaptor = slot<Cookie>()

            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns String(Base64.getEncoder().encode("invalidCookie".toByteArray()))
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { response.addCookie(capture(cancelCookieCaptor)) } just Runs

            service.autoLogin(request, response)
            assertThat(cancelCookieCaptor.isCaptured).isTrue
            assertCancelCookie(cancelCookieCaptor.captured)
        }

        @Test
        fun `token is not registered in repository`() {
            val cancelCookieCaptor = slot<Cookie>()

            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns savedCookieValue("series", "value")
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { repository.findById(RememberMeTokenSeries("series")) } returns Optional.empty()
            every { response.addCookie(capture(cancelCookieCaptor)) } just Runs

            service.autoLogin(request, response)
            assertThat(cancelCookieCaptor.isCaptured).isTrue
            assertCancelCookie(cancelCookieCaptor.captured)
        }

        @Test
        fun `token value is not matches`() {
            val persistedToken: RememberMeToken = mockk {
                every { series } returns RememberMeTokenSeries("series")
                every { tokenValue } returns RememberMeTokenValue("different")
            }
            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns savedCookieValue("series", "value")
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { repository.findById(RememberMeTokenSeries("series")) } returns Optional.of(persistedToken)

            val thrown = catchThrowable { service.autoLogin(request, response) }
            assertThat(thrown).isInstanceOf(CookieTheftException::class.java)
            verify { repository.delete(persistedToken) }
        }

        @Test
        fun `token is expired`() {
            val cancelCookieCaptor = slot<Cookie>()

            val persistedToken: RememberMeToken = mockk {
                every { series } returns RememberMeTokenSeries("series")
                every { tokenValue } returns RememberMeTokenValue("value")
                every { isExpired() } returns true
            }
            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns savedCookieValue("series", "value")
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { repository.findById(RememberMeTokenSeries("series")) } returns Optional.of(persistedToken)
            every { response.addCookie(capture(cancelCookieCaptor)) } just Runs

            service.autoLogin(request, response)
            assertThat(cancelCookieCaptor.isCaptured).isTrue
            assertCancelCookie(cancelCookieCaptor.captured)
            verify { repository.delete(persistedToken) }
        }

        @Test
        fun `auto login successful`() {
            val persistedUser: UserDetails = mockk(relaxed = true)
            val persistedToken: RememberMeToken = mockk(relaxed = true) {
                every { series } returns RememberMeTokenSeries("series")
                every { tokenValue } returns RememberMeTokenValue("value")
                every { username } returns RememberMePrincipal("username")
                every { isExpired() } returns false
            }
            val cookie: Cookie = mockk {
                every { name } returns rememberMeCookieName
                every { value } returns savedCookieValue("series", "value")
            }
            val request: HttpServletRequest = mockk(relaxed = true) {
                every { cookies } returns arrayOf(cookie)
            }
            val response: HttpServletResponse = mockk(relaxed = true)

            every { checker.check(persistedUser) } just Runs
            every { userDetailsService.loadUserByUsername("username") } returns persistedUser
            every { repository.save(persistedToken) } returnsArgument 0
            every { repository.findById(RememberMeTokenSeries("series")) } returns Optional.of(persistedToken)

            val result = service.autoLogin(request, response)
            assertThat(result).isInstanceOf(RememberMeAuthenticationToken::class.java)
            assertThat(result.principal).isEqualTo(persistedUser)
            verifyOrder {
                persistedToken.updateLastUsedAt()
                repository.save(persistedToken)
            }
        }

        private fun assertCancelCookie(cookie: Cookie) {
            assertThat(cookie.name).isEqualTo(rememberMeCookieName)
            assertThat(cookie.value).isNull()
            assertThat(cookie.maxAge).isZero
        }
    }

    private fun savedCookieValue(tokenSeries: String, tokenValue: String): String {
        val cookieValue = "${tokenSeries}:${tokenValue}"

        val base64 = Base64.getEncoder().encode(cookieValue.toByteArray())
        val builder = StringBuilder(String(base64))
        while (builder.last() == '=') {
            builder.deleteCharAt(builder.length - 1)
        }
        return builder.toStr()
    }
}