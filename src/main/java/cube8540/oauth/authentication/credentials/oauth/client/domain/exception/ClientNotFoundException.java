package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientNotFoundException extends RuntimeException {

    private final String code;
    private final String description;

    public static ClientNotFoundException instance(String description) {
        return new ClientNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
