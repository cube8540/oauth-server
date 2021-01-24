package cube8540.oauth.authentication.error.security;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
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

@DisplayName("접근 거부 예외 응답 메시지 클래스 테스트")
public class AccessDeniedExceptionResponseRendererTest {

    @Test
    @DisplayName("지원 되지 않는 미디어 타입으로 객체 생성")
    @SuppressWarnings("unchecked")
    void createObjectByNotSupportedMediaType() {
        HttpMessageConverter<Object> messageConverter = mock(HttpMessageConverter.class);

        when(messageConverter.canWrite(ErrorMessage.class, MediaType.APPLICATION_JSON)).thenReturn(false);

        assertThrows(HttpMediaTypeNotSupportedException.class, () -> new AccessDeniedExceptionResponseRenderer(messageConverter));
    }

    @Test
    @DisplayName("응답 객체에 ResponseEntity 에 저장된 HTTP 상태 코드 복사")
    void copyHttpStatusCodeInResponseEntityToResponseObject() {
        HttpMessageConverter<Object> messageConverter = makeDefaultMessageConverter();
        ResponseEntity<ErrorMessage<Object>> responseEntity = makeAccessDeniedResponseEntity(makeAccessDeniedErrorMessage());
        AccessDeniedExceptionResponseRenderer renderer = new AccessDeniedExceptionResponseRenderer(messageConverter);
        ServletWebRequest webRequest = makeServletWebRequest();

        renderer.rendering(responseEntity, webRequest);
        verify(webRequest.getResponse(), times(1)).setStatus(HttpStatus.FORBIDDEN.value());
    }

    @Test
    @DisplayName("ResponseEntity 의 Body가 null 일때 응답 객체에 응답 메시지를 쓰지 않아야 한다.")
    void whenResponseEntityBodyNullDoesNotWriteResponseMessage() throws Exception {
        HttpMessageConverter<Object> messageConverter = makeDefaultMessageConverter();
        ResponseEntity<ErrorMessage<Object>> responseEntity = makeAccessDeniedResponseEntity(null);
        AccessDeniedExceptionResponseRenderer renderer = new AccessDeniedExceptionResponseRenderer(messageConverter);
        ServletWebRequest webRequest = makeServletWebRequest();

        renderer.rendering(responseEntity, webRequest);
        verify(messageConverter, never()).write(any(), any(), any());
    }

    @Test
    @DisplayName("컨버터를 이용한 응답 메시지 작성")
    void writeResponseMessageByConverter() throws Exception {
        HttpMessageConverter<Object> messageConverter = makeDefaultMessageConverter();
        ArgumentCaptor<ServletServerHttpResponse> responseCaptor = ArgumentCaptor.forClass(ServletServerHttpResponse.class);
        ErrorMessage<Object> errorMessage = makeAccessDeniedErrorMessage();
        ResponseEntity<ErrorMessage<Object>> responseEntity = makeAccessDeniedResponseEntity(errorMessage);
        AccessDeniedExceptionResponseRenderer renderer = new AccessDeniedExceptionResponseRenderer(messageConverter);
        ServletWebRequest webRequest = makeServletWebRequest();

        renderer.rendering(responseEntity, webRequest);
        verify(messageConverter, times(1)).write(eq(errorMessage), eq(MediaType.APPLICATION_JSON), responseCaptor.capture());
        responseCaptor.getValue().getBody(); // header flush
        assertEquals(webRequest.getResponse(), responseCaptor.getValue().getServletResponse());
    }

    @SuppressWarnings("unchecked")
    private HttpMessageConverter<Object> makeDefaultMessageConverter() {
        HttpMessageConverter<Object> messageConverter = mock(HttpMessageConverter.class);
        when(messageConverter.canWrite(any(), any())).thenReturn(true);
        return messageConverter;
    }

    private ServletWebRequest makeServletWebRequest() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        return new ServletWebRequest(request, response);
    }

    private HttpHeaders makeResponseHeader() {
        HttpHeaders headers = new HttpHeaders();

        headers.setCacheControl(CacheControl.noStore());
        headers.setPragma("no-cache");
        return headers;
    }

    private ErrorMessage<Object> makeAccessDeniedErrorMessage() {
        return ErrorMessage.instance(ErrorCodes.ACCESS_DENIED, "TEST");
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<ErrorMessage<Object>> makeAccessDeniedResponseEntity(ErrorMessage<Object> errorMessage) {
        ResponseEntity<ErrorMessage<Object>> responseEntity = mock(ResponseEntity.class);

        when(responseEntity.getBody()).thenReturn(errorMessage);
        when(responseEntity.getStatusCode()).thenReturn(HttpStatus.FORBIDDEN);
        when(responseEntity.getHeaders()).thenReturn(makeResponseHeader());

        return responseEntity;
    }
}
