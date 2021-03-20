package cube8540.oauth.authentication.oauth.error

import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.web.HttpRequestMethodNotSupportedException
import java.util.stream.Stream

class OAuth2ExceptionTranslatorTest {

    private val translator = OAuth2ExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["abstractOAuth2AuthenticationException"])
    fun `translate abstract oauth2 authentication exception`(exception: AbstractOAuth2AuthenticationException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.valueOf(exception.statusCode))
        assertThat(result.body).isEqualTo(exception.error)
        assertThat(result.headers[HttpHeaders.CACHE_CONTROL]).isEqualTo(listOf("no-store"))
        assertThat(result.headers.pragma).isEqualTo("no-cache")
    }

    @ParameterizedTest
    @MethodSource(value = ["httpRequestMethodNotSupportedException"])
    fun `translate http request method not supported exception`(exception: HttpRequestMethodNotSupportedException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED)
        assertThat(result.body!!.errorCode).isEqualTo("method_not_allowed")
        assertThat(result.body!!.description).isEqualTo(exception.message)
        assertThat(result.headers[HttpHeaders.CACHE_CONTROL]).isEqualTo(listOf("no-store"))
        assertThat(result.headers.pragma).isEqualTo("no-cache")
    }

    @ParameterizedTest
    @MethodSource(value = ["oauth2ClientRegistrationException"])
    fun `translate oauth2 client registration exception`(exception: OAuth2ClientRegistrationException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
        assertThat(result.body!!.errorCode).isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        assertThat(result.body!!.description).isEqualTo(exception.message)
        assertThat(result.headers[HttpHeaders.CACHE_CONTROL]).isEqualTo(listOf("no-store"))
        assertThat(result.headers.pragma).isEqualTo("no-cache")
    }

    @ParameterizedTest
    @MethodSource(value = ["oauth2AccessTokenRegistrationException"])
    fun `translate oauth2 access token registration exception`(exception: OAuth2AccessTokenRegistrationException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
        assertThat(result.body!!.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        assertThat(result.body!!.description).isEqualTo(exception.message)
        assertThat(result.headers[HttpHeaders.CACHE_CONTROL]).isEqualTo(listOf("no-store"))
        assertThat(result.headers.pragma).isEqualTo("no-cache")
    }

    @Test
    fun `translate another exception`() {
        val exception = Exception("exception")
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR)
        assertThat(result.body!!.errorCode).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR)
        assertThat(result.body!!.description).isEqualTo(exception.message)
        assertThat(result.headers[HttpHeaders.CACHE_CONTROL]).isEqualTo(listOf("no-store"))
        assertThat(result.headers.pragma).isEqualTo("no-cache")
    }

    private fun abstractOAuth2AuthenticationException() = Stream.of(
        Arguments.of(
            mockk<AbstractOAuth2AuthenticationException> {
                every { statusCode } returns 400
                every { error } returns mockk()
            }
        ),
        Arguments.of(
            mockk<AbstractOAuth2AuthenticationException> {
                every { statusCode } returns 404
                every { error } returns mockk()
            }
        ),
        Arguments.of(
            mockk<AbstractOAuth2AuthenticationException> {
                every { statusCode } returns 500
                every { error } returns mockk()
            }
        )
    )

    private fun httpRequestMethodNotSupportedException() = Stream.of(
        Arguments.of(HttpRequestMethodNotSupportedException("method not supported"))
    )

    private fun oauth2ClientRegistrationException() = Stream.of(
        Arguments.of(OAuth2ClientRegistrationException("client registration exception"))
    )

    private fun oauth2AccessTokenRegistrationException() = Stream.of(
        Arguments.of(OAuth2AccessTokenRegistrationException("token registration exception"))
    )
}