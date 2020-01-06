package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Objects;

public class DefaultOauth2ExceptionResponseRenderer implements OAuth2ExceptionResponseRenderer {

    private final HttpMessageConverter<Object> messageConverter;

    private final MediaType supportMediaType;

    public DefaultOauth2ExceptionResponseRenderer(HttpMessageConverter<Object> messageConverter)
            throws HttpMediaTypeNotSupportedException {
        this(messageConverter, MediaType.ALL);
    }

    public DefaultOauth2ExceptionResponseRenderer(HttpMessageConverter<Object> messageConverter, MediaType supportMediaType)
            throws HttpMediaTypeNotSupportedException {
        this.messageConverter = messageConverter;
        this.supportMediaType = supportMediaType;

        if (!messageConverter.canWrite(Object.class, supportMediaType)) {
            throw new HttpMediaTypeNotSupportedException(supportMediaType + " is not supported");
        }
    }

    @Override
    public void rendering(ResponseEntity<OAuth2Error> responseEntity, ServletWebRequest webRequest) throws Exception {
        if (responseEntity == null) {
            return;
        }
        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(Objects.requireNonNull(webRequest.getResponse()));
        outputMessage.setStatusCode(responseEntity.getStatusCode());
        if (!responseEntity.getHeaders().isEmpty()) {
            outputMessage.getHeaders().putAll(responseEntity.getHeaders());
        }
        OAuth2Error body = responseEntity.getBody();
        if (body != null) {
            messageConverter.write(body, supportMediaType, outputMessage);
        } else {
            outputMessage.getBody();
        }
    }
}