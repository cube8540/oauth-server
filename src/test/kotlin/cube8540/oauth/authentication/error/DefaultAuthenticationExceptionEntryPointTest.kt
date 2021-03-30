package cube8540.oauth.authentication.error

import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.http.ResponseEntity
import org.springframework.security.core.AuthenticationException
import org.springframework.web.context.request.ServletWebRequest
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class DefaultAuthenticationExceptionEntryPointTest {

    private val translator: ExceptionTranslator<Any> = mockk()
    private val renderer: ExceptionResponseRenderer<Any> = mockk()

    private val entryPoint = DefaultAuthenticationExceptionEntryPoint(translator, renderer)

    @Test
    fun `rendering response message`() {
        val requestCaptor = slot<ServletWebRequest>()

        val responseEntity: ResponseEntity<Any> = mockk(relaxed = true)
        val exception: AuthenticationException = mockk(relaxed = true)
        val request: HttpServletRequest = mockk(relaxed = true)
        val response: HttpServletResponse = mockk(relaxed = true)

        every { translator.translate(exception) } returns responseEntity
        every { renderer.rendering(eq(responseEntity), capture(requestCaptor)) } just Runs

        entryPoint.commence(request, response, exception)
        assertThat(requestCaptor.isCaptured).isTrue
        assertThat(requestCaptor.captured.request).isEqualTo(request)
        assertThat(requestCaptor.captured.response).isEqualTo(response)
        verifyOrder {
            renderer.rendering(responseEntity, requestCaptor.captured)
            response.flushBuffer()
        }
    }
}