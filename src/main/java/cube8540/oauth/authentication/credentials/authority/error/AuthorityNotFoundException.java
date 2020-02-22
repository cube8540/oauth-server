package cube8540.oauth.authentication.credentials.authority.error;

import lombok.Getter;

@Getter
public class AuthorityNotFoundException extends RuntimeException {

    private String code;
    private String description;

    public AuthorityNotFoundException(String description) {
        this.code = AuthorityErrorCodes.NOT_FOUND;
        this.description = description;
    }
}
