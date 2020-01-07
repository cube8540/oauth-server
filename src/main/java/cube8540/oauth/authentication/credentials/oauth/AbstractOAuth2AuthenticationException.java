package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public abstract class AbstractOAuth2AuthenticationException extends OAuth2AuthenticationException {

    private int statusCode;

    public AbstractOAuth2AuthenticationException(int statusCode, OAuth2Error error) {
        super(error);
        this.statusCode = statusCode;
    }

    public AbstractOAuth2AuthenticationException(int statusCode, OAuth2Error error, Throwable cause) {
        super(error, cause);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        String delimiter = ", ";

        builder.append("error=\"").append(getError().getErrorCode()).append("\"");

        String errorMessage = getError().getDescription();
        if (errorMessage != null) {
            builder.append(delimiter).append("error_description=\"").append(errorMessage).append("\"");
        }

        return builder.toString();
    }
}
