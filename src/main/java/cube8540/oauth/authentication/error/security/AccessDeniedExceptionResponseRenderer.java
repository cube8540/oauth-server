package cube8540.oauth.authentication.error.security;

import cube8540.oauth.authentication.error.ExceptionResponseRenderer;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Objects;

public class AccessDeniedExceptionResponseRenderer implements ExceptionResponseRenderer<ErrorMessage<Object>> {

    private final HttpMessageConverter<Object> messageConverter;

    public AccessDeniedExceptionResponseRenderer(HttpMessageConverter<Object> messageConverter) throws HttpMediaTypeNotSupportedException {
        this.messageConverter = messageConverter;

        if (!messageConverter.canWrite(ErrorMessage.class, MediaType.APPLICATION_JSON)) {
            throw new HttpMediaTypeNotSupportedException("application/json media type not supported");
        }
    }

    @Override
    public void rendering(ResponseEntity<ErrorMessage<Object>> responseEntity, ServletWebRequest webRequest) throws Exception {
        if (responseEntity == null) {
            return;
        }
        try (ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(Objects.requireNonNull(webRequest.getResponse()))) {
            outputMessage.setStatusCode(responseEntity.getStatusCode());
            if (!responseEntity.getHeaders().isEmpty()) {
                outputMessage.getHeaders().putAll(responseEntity.getHeaders());
            }
            ErrorMessage<Object> body = responseEntity.getBody();
            if (body != null) {
                messageConverter.write(body, MediaType.APPLICATION_JSON, outputMessage);
            } else {
                outputMessage.getBody();
            }
        }
    }
}
