package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public abstract class AbstractOAuth2AuthenticationException extends OAuth2AuthenticationException {

    private int code;

    public AbstractOAuth2AuthenticationException(int code, OAuth2Error error) {
        super(error);
        this.code = code;
    }

    public AbstractOAuth2AuthenticationException(int code, OAuth2Error error, String message) {
        super(error, message);
        this.code = code;
    }

    public AbstractOAuth2AuthenticationException(int code, OAuth2Error error, Throwable cause) {
        super(error, cause);
        this.code = code;
    }

    public AbstractOAuth2AuthenticationException(int code, OAuth2Error error, String message, Throwable cause) {
        super(error, message, cause);
        this.code = code;
    }

    public int getCode() {
        return code;
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
