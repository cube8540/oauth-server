package cube8540.oauth.authentication.error

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.web.context.request.ServletWebRequest
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class DefaultAuthenticationExceptionEntryPoint<T>(
    private val translator: ExceptionTranslator<T>,

    private val renderer: ExceptionResponseRenderer<T>
): AuthenticationEntryPoint {

    override fun commence(request: HttpServletRequest, response: HttpServletResponse, authException: AuthenticationException) {
        val responseEntity = translator.translate(authException)

        renderer.rendering(responseEntity, ServletWebRequest(request, response))
        response.flushBuffer()
    }
}