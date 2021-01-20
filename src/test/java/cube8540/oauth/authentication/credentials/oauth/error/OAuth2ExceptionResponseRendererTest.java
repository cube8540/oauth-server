package cube8540.oauth.authentication.credentials.oauth.error;

import org.junit.jupiter.api.DisplayName;
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
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 기본 예외 응답 메시지 클래스 테스트")
class OAuth2ExceptionResponseRendererTest {

    @Test
    @DisplayName("지원 되지 않는 미디어 타입으로 클래스 초기화")
    void initializeByNotSupportedMediaType() {
        HttpMessageConverter<Object> messageConverter = makeConverter();

        when(messageConverter.canWrite(any(), any())).thenReturn(false);

        assertThrows(HttpMediaTypeNotSupportedException.class, () -> new OAuth2ExceptionResponseRenderer(messageConverter));
    }

    @Test
    @DisplayName("ResponseEntity의 body가 null 일때 응답 객체에 메시지 작성")
    void writeResponseMessageToResponseObjectWhenResponseEntityBodyIsNull() throws Exception {
        HttpMessageConverter<Object> messageConverter = makeConverter();
        ResponseEntity<OAuth2Error> responseEntity = makeResponseEntity(null);
        OAuth2ExceptionResponseRenderer renderer = new OAuth2ExceptionResponseRenderer(messageConverter);
        ServletWebRequest webRequest = makeWebRequest();

        renderer.rendering(responseEntity, webRequest);
        verify(webRequest.getResponse(), times(1)).setStatus(HttpStatus.UNAUTHORIZED.value());
        verify(webRequest.getResponse(), times(1)).addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue());
        verify(webRequest.getResponse(), times(1)).addHeader(HttpHeaders.PRAGMA, "no-cache");
        verify(messageConverter, never()).write(any(), any(), any());
    }

    @Test
    @DisplayName("응답 객체에 메시지 작성")
    void writeResponseMessageToResponseObject() throws Exception {
        OAuth2Error error = mock(OAuth2Error.class);
        HttpMessageConverter<Object> messageConverter = makeConverter();
        ResponseEntity<OAuth2Error> responseEntity = makeResponseEntity(error);
        ArgumentCaptor<ServletServerHttpResponse> responseCaptor = ArgumentCaptor.forClass(ServletServerHttpResponse.class);
        ServletWebRequest webRequest = makeWebRequest();
        OAuth2ExceptionResponseRenderer renderer = new OAuth2ExceptionResponseRenderer(messageConverter);

        renderer.rendering(responseEntity, webRequest);
        verify(webRequest.getResponse(), times(1)).setStatus(HttpStatus.UNAUTHORIZED.value());
        verify(messageConverter, times(1)).write(eq(error), eq(MediaType.ALL), responseCaptor.capture());
        responseCaptor.getValue().getBody(); // header flush
        verify(webRequest.getResponse(), times(1)).addHeader(HttpHeaders.CACHE_CONTROL, CacheControl.noStore().getHeaderValue());
        verify(webRequest.getResponse(), times(1)).addHeader(HttpHeaders.PRAGMA, "no-cache");
        assertEquals(webRequest.getResponse(), responseCaptor.getValue().getServletResponse());
    }

    @SuppressWarnings("unchecked")
    private HttpMessageConverter<Object> makeConverter() {
        HttpMessageConverter<Object> converter = mock(HttpMessageConverter.class);

        when(converter.canWrite(any(), any())).thenReturn(true);

        return converter;
    }

    private HttpHeaders makeHeaders() {
        HttpHeaders header = new HttpHeaders();

        header.setCacheControl(CacheControl.noStore());
        header.setPragma("no-cache");

        return header;
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<OAuth2Error> makeResponseEntity(OAuth2Error body) {
        ResponseEntity<OAuth2Error>responseEntity = mock(ResponseEntity.class);

        when(responseEntity.getBody()).thenReturn(body);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.UNAUTHORIZED);
        when(responseEntity.getHeaders()).thenReturn(makeHeaders());

        return responseEntity;
    }

    private ServletWebRequest makeWebRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        return new ServletWebRequest(request, response);
    }
}