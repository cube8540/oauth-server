package cube8540.oauth.authentication.credentials.authority.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ResourceNotFoundException extends RuntimeException {

    private final String code;
    private final String description;

    public static ResourceNotFoundException instance(String description) {
        return new ResourceNotFoundException(ErrorCodes.NOT_FOUND, description);
    }

}
