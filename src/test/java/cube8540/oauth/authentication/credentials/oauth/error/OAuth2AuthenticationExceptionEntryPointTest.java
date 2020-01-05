package cube8540.oauth.authentication.credentials.oauth.error;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
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
class OAuth2AuthenticationExceptionEntryPointTest {

    private OAuth2ExceptionTranslator translator;
    private OAuth2ExceptionResponseRenderer renderer;

    private OAuth2AuthenticationExceptionEntryPoint entryPoint;

    @BeforeEach
    void setup() {
        this.translator = mock(OAuth2ExceptionTranslator.class);
        this.renderer = mock(OAuth2ExceptionResponseRenderer.class);

        this.entryPoint = new OAuth2AuthenticationExceptionEntryPoint(translator, renderer);
    }

    @Nested
    @DisplayName("예외 처리")
    class Commences {
        private ResponseEntity<OAuth2Error> responseEntity;
        private AuthenticationException exception;
        private HttpServletRequest request;
        private HttpServletResponse response;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            this.responseEntity = mock(ResponseEntity.class);
            this.exception = mock(AuthenticationException.class);
            this.request = mock(HttpServletRequest.class);
            this.response = mock(HttpServletResponse.class);

            when(translator.translate(exception)).thenReturn(responseEntity);
        }

        @Test
        @DisplayName("Renderer을 이용하여 응답 메시지를 작성해야 한다.")
        void shouldUsingRenderer() throws Exception {
            ArgumentCaptor<ServletWebRequest> requestCaptor = ArgumentCaptor.forClass(ServletWebRequest.class);

            entryPoint.commence(request, response, exception);
            verify(renderer, times(1)).rendering(eq(responseEntity), requestCaptor.capture());
            assertEquals(request, requestCaptor.getValue().getRequest());
            assertEquals(response, requestCaptor.getValue().getResponse());
        }

        @Test
        @DisplayName("Response 객체의 버퍼를 비워야 한다.")
        void shouldFlushBufferResponse() throws Exception {
            entryPoint.commence(request, response, exception);
            verify(response, times(1)).flushBuffer();
        }
    }
}