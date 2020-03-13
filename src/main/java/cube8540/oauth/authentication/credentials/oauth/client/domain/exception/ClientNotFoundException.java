package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ClientRegistrationException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.Getter;

@Getter
public class ClientNotFoundException extends OAuth2ClientRegistrationException {

    private final String code;
    private final String description;

    private ClientNotFoundException(String code, String description) {
        super(description);
        this.code = code;
        this.description = description;
    }

    public static ClientNotFoundException instance(String description) {
        return new ClientNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
