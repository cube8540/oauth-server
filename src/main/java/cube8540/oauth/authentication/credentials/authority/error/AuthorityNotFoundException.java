package cube8540.oauth.authentication.credentials.authority.error;

public class AuthorityNotFoundException extends RuntimeException {

    private String code;
    private String description;

    public AuthorityNotFoundException(String description) {
        this.code = AuthorityErrorCodes.NOT_FOUND;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
