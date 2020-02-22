package cube8540.oauth.authentication.credentials.authority.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthorityRegisterException extends RuntimeException {

    private String code;
    private String description;

    public static AuthorityRegisterException existsIdentifier(String description) {
        return new AuthorityRegisterException(AuthorityErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
