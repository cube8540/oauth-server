package cube8540.oauth.authentication.oauth.error

import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.springframework.http.*
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.web.HttpMediaTypeNotSupportedException
import org.springframework.web.context.request.ServletWebRequest
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class OAuth2ExceptionResponseRendererTest {

    @Nested
    inner class InitializationTest {
        private val messageConverter: HttpMessageConverter<Any> = mockk()

        @Test
        fun `message converter is not supported media type`() {
            every { messageConverter.canWrite(OAuth2Error::class.java, MediaType.APPLICATION_JSON) } returns false

            val thrown = catchThrowable { OAuth2ExceptionResponseRenderer(messageConverter, MediaType.APPLICATION_JSON) }
            assertThat(thrown).isInstanceOf(HttpMediaTypeNotSupportedException::class.java)
        }

        @Test
        fun `message converter is supported media type`() {
            every { messageConverter.canWrite(OAuth2Error::class.java, MediaType.APPLICATION_JSON) } returns true

            assertDoesNotThrow { OAuth2ExceptionResponseRenderer(messageConverter, MediaType.APPLICATION_JSON) }
        }
    }

    @Nested
    inner class RenderingTest {
        private val messageConverter: HttpMessageConverter<Any> = mockk(relaxed = true) {
            every { canWrite(OAuth2Error::class.java, MediaType.APPLICATION_JSON) } returns true
        }
        private val renderer = OAuth2ExceptionResponseRenderer(messageConverter, MediaType.APPLICATION_JSON)

        @Test
        fun `rendering response when body is null`() {
            val httpHeaders = HttpHeaders()
            val responseEntity: ResponseEntity<OAuth2Error> = mockk {
                every { body } returns null
                every { statusCode } returns HttpStatus.BAD_REQUEST
                every { headers } returns httpHeaders
            }
            val httpServletRequest: HttpServletRequest = mockk(relaxed = true)
            val httpServletResponse: HttpServletResponse = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk {
                every { request } returns httpServletRequest
                every { response } returns httpServletResponse
            }

            httpHeaders.setCacheControl(CacheControl.noStore())
            httpHeaders.pragma = "no-cache"

            renderer.rendering(responseEntity, webRequest)
            verify { httpServletResponse.status = HttpStatus.BAD_REQUEST.value() }
            verify { httpServletResponse.addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().headerValue) }
            verify { httpServletResponse.addHeader(HttpHeaders.PRAGMA, "no-cache") }
            verify(exactly = 0) { messageConverter.write(any(), any(), any()) }
        }

        @Test
        fun `rendering response when body is not null`() {
            val responseCaptor = slot<ServletServerHttpResponse>()
            val httpHeaders = HttpHeaders()
            val errorBody: OAuth2Error = mockk()
            val responseEntity: ResponseEntity<OAuth2Error> = mockk {
                every { body } returns errorBody
                every { statusCode } returns HttpStatus.BAD_REQUEST
                every { headers } returns httpHeaders
            }
            val httpServletRequest: HttpServletRequest = mockk(relaxed = true)
            val httpServletResponse: HttpServletResponse = mockk(relaxed = true)
            val webRequest: ServletWebRequest = mockk {
                every { request } returns httpServletRequest
                every { response } returns httpServletResponse
            }

            httpHeaders.setCacheControl(CacheControl.noStore())
            httpHeaders.pragma = "no-cache"

            renderer.rendering(responseEntity, webRequest)
            verify { messageConverter.write(eq(errorBody), eq(MediaType.APPLICATION_JSON), capture(responseCaptor)) }
            assertThat(responseCaptor.isCaptured).isTrue
            responseCaptor.captured.body // header flush
            verify { httpServletResponse.status = HttpStatus.BAD_REQUEST.value() }
            verify { httpServletResponse.addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().headerValue) }
            verify { httpServletResponse.addHeader(HttpHeaders.PRAGMA, "no-cache") }
            assertThat(httpServletResponse).isEqualTo(responseCaptor.captured.servletResponse)
        }
    }
}