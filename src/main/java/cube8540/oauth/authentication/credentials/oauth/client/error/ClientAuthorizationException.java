package cube8540.oauth.authentication.credentials.oauth.client.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientAuthorizationException extends RuntimeException {

    private String code;

    private String description;

    public static ClientAuthorizationException invalidOwner(String description) {
        return new ClientAuthorizationException(ClientErrorCodes.INVALID_OWNER, description);
    }

    public static ClientAuthorizationException invalidPassword(String description) {
        return new ClientAuthorizationException(ClientErrorCodes.INVALID_PASSWORD, description);
    }

}
