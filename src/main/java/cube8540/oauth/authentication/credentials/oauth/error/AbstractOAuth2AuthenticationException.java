package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public abstract class AbstractOAuth2AuthenticationException extends AuthenticationException {

    private final OAuth2Error error;
    private final int statusCode;

    public AbstractOAuth2AuthenticationException(int statusCode, OAuth2Error error) {
        super(error.getDescription());
        this.error = error;
        this.statusCode = statusCode;
    }

    public OAuth2Error getError() {
        return error;
    }

    public int getStatusCode() {
        return statusCode;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        String delimiter = ", ";

        builder.append("error=\"").append(error.getErrorCode()).append("\"");

        String errorMessage = error.getDescription();
        if (errorMessage != null) {
            builder.append(delimiter).append("error_description=\"").append(errorMessage).append("\"");
        }

        return builder.toString();
    }
}
