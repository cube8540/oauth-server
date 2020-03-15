package cube8540.oauth.authentication.error;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class DefaultAuthenticationExceptionEntryPoint<T> implements AuthenticationEntryPoint {

    private final ExceptionTranslator<T> translator;
    private final ExceptionResponseRenderer<T> responseRenderer;

    public DefaultAuthenticationExceptionEntryPoint(ExceptionTranslator<T> translator, ExceptionResponseRenderer<T> responseRenderer) {
        this.translator = translator;
        this.responseRenderer = responseRenderer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        try {
            ResponseEntity<T> responseEntity = translator.translate(authException);
            responseRenderer.rendering(responseEntity, new ServletWebRequest(request, response));
            response.flushBuffer();
        } catch(ServletException | IOException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
