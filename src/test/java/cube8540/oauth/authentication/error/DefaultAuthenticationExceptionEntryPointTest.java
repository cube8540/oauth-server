package cube8540.oauth.authentication.error;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 보안 예외 처리 엔트리 클래스 테스트")
class DefaultAuthenticationExceptionEntryPointTest {

    private ExceptionTranslator<Object> translator;
    private ExceptionResponseRenderer<Object> renderer;

    private DefaultAuthenticationExceptionEntryPoint<Object> entryPoint;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setup() {
        this.translator = mock(ExceptionTranslator.class);
        this.renderer = mock(ExceptionResponseRenderer.class);

        this.entryPoint = new DefaultAuthenticationExceptionEntryPoint<>(translator, renderer);
    }

    @Test
    @DisplayName("응답 메시지 작성")
    @SuppressWarnings("unchecked")
    void renderingResponseMessage() throws Exception {
        ResponseEntity<Object> responseEntity = mock(ResponseEntity.class);
        AuthenticationException exception = mock(AuthenticationException.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(translator.translate(exception)).thenReturn(responseEntity);

        ArgumentCaptor<ServletWebRequest> requestCaptor = ArgumentCaptor.forClass(ServletWebRequest.class);
        entryPoint.commence(request, response, exception);
        verify(renderer, times(1)).rendering(eq(responseEntity), requestCaptor.capture());
        verify(response, times(1)).flushBuffer();
        assertEquals(request, requestCaptor.getValue().getRequest());
        assertEquals(response, requestCaptor.getValue().getResponse());
    }
}