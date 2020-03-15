package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.error.ExceptionResponseRenderer;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OAuth2AuthenticationExceptionEntryPoint implements AuthenticationEntryPoint {

    private final ExceptionTranslator<OAuth2Error> translator;
    private final ExceptionResponseRenderer<OAuth2Error> responseRenderer;

    public OAuth2AuthenticationExceptionEntryPoint(ExceptionTranslator<OAuth2Error> translator, ExceptionResponseRenderer<OAuth2Error> responseRenderer) {
        this.translator = translator;
        this.responseRenderer = responseRenderer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        try {
            ResponseEntity<OAuth2Error> responseEntity = translator.translate(authException);
            responseRenderer.rendering(responseEntity, new ServletWebRequest(request, response));
            response.flushBuffer();
        } catch(ServletException | IOException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
