package cube8540.oauth.authentication.credentials.oauth.error;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 기본 예외 응답 메시지 클래스 테스트")
class OAuth2ExceptionResponseRendererTest {

    private HttpServletRequest request0;
    private HttpServletResponse response0;
    private ServletWebRequest webRequest0;
    private HttpMessageConverter<Object> messageConverter;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setup() {
        this.messageConverter = mock(HttpMessageConverter.class);
        this.request0 = mock(HttpServletRequest.class);
        this.response0 = mock(HttpServletResponse.class);
        this.webRequest0 = new ServletWebRequest(request0, response0);
    }

    @Nested
    @DisplayName("객체 생성")
    class InitializeRenderer {

        @Nested
        @DisplayName("지원되지 않는 미디어 타입일시")
        class WhenNotSupportedMediaType {

            @BeforeEach
            void setup() {
                when(messageConverter.canWrite(any(), any())).thenReturn(false);
            }

            @Test
            @DisplayName("HttpMediaTypeNotSupportedException이 발생해야 한다.")
            void shouldThrowsHttpMediaTypeNotSupportedException() {
                assertThrows(HttpMediaTypeNotSupportedException.class, () -> new OAuth2ExceptionResponseRenderer(messageConverter));
            }
        }
    }

    @Nested
    @DisplayName("Response 객체에 응답 메시지를 작성")
    class WriteResponseMessage {
        private OAuth2ExceptionResponseRenderer renderer;

        @BeforeEach
        void setup() throws Exception {
            when(messageConverter.canWrite(any(), any())).thenReturn(true);
            this.renderer = new OAuth2ExceptionResponseRenderer(messageConverter);
        }

        @Nested
        @DisplayName("ResponseEntity가 null일시")
        class WhenResponseEntityNull {

            @Test
            @DisplayName("아무 행동도 하지 않아야 한다.")
            void shouldDoNothing() throws Exception {
                renderer.rendering(null, webRequest0);
                verifyNoMoreInteractions(response0);
            }
        }

        @Nested
        @DisplayName("ResponserEntity가 null이 아닐시")
        class WhenResponseEntityNotNull {
            private OAuth2Error error0;
            private ResponseEntity<OAuth2Error> responseEntity0;
            private HttpHeaders headers = new HttpHeaders();

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                this.error0 = mock(OAuth2Error.class);
                this.responseEntity0 = mock(ResponseEntity.class);

                when(responseEntity0.getBody()).thenReturn(error0);
                when(responseEntity0.getStatusCode()).thenReturn(HttpStatus.UNAUTHORIZED);
                when(responseEntity0.getHeaders()).thenReturn(headers);
                headers.setCacheControl(CacheControl.noStore());
                headers.setPragma("no-cache");
            }

            @Test
            @DisplayName("응답 객체에 ResponseEntity에 저장된 HTTP 상태 코드를 복사해야 한다.")
            void shouldCopyResponseEntityHttpStatusCode() throws Exception {
                renderer.rendering(responseEntity0, webRequest0);

                verify(response0, times(1)).setStatus(HttpStatus.UNAUTHORIZED.value());
            }

            @Nested
            @DisplayName("ResponseEntity의 Body가 null일시")
            class WhenResponseEntityBodyNull {

                @BeforeEach
                void setup() {
                    when(responseEntity0.getBody()).thenReturn(null);
                }

                @Test
                @DisplayName("응답 객체에 ResponseEntity에 저장된 헤더를 복사해야 한다.")
                void shouldCopyResponseEntityHeaders() throws Exception {
                    renderer.rendering(responseEntity0, webRequest0);
                    verify(response0, times(1)).addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue());
                    verify(response0, times(1)).addHeader(HttpHeaders.PRAGMA, "no-cache");
                }

                @Test
                @DisplayName("컨버터를 이용하여 응답 객체에 응답 메시지를 쓰지 않아야 한다.")
                void shouldDontWriteResponseMessageByConverter() throws Exception {
                    renderer.rendering(responseEntity0, webRequest0);
                    verify(messageConverter, never()).write(any(), any(), any());
                }
            }

            @Nested
            @DisplayName("ResponseEntity의 Body가 null이 아닐시")
            class WhenResponseEntityBodyNotNull {

                @Test
                @DisplayName("응답 객체에 ResponseEntity에 저장된 헤더를 복사해야 한다.")
                void shouldCopyResponseEntityHeaders() throws Exception {
                    ArgumentCaptor<ServletServerHttpResponse> responseCaptor = ArgumentCaptor.forClass(ServletServerHttpResponse.class);

                    renderer.rendering(responseEntity0, webRequest0);
                    verify(messageConverter, times(1)).write(eq(error0), eq(MediaType.ALL), responseCaptor.capture());
                    responseCaptor.getValue().getBody(); // header flush
                    verify(response0, times(1)).addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue());
                    verify(response0, times(1)).addHeader(HttpHeaders.PRAGMA, "no-cache");
                }

                @Test
                @DisplayName("컨버터를 이용하여 응답 객체에 응답 메시지를 써야 한다.")
                void shouldWriteResponseMessageByConverter() throws Exception {
                    ArgumentCaptor<ServletServerHttpResponse> responseCaptor = ArgumentCaptor.forClass(ServletServerHttpResponse.class);

                    renderer.rendering(responseEntity0, webRequest0);
                    verify(messageConverter, times(1)).write(eq(error0), eq(MediaType.ALL), responseCaptor.capture());
                    assertEquals(response0, responseCaptor.getValue().getServletResponse());
                }
            }
        }
    }
}