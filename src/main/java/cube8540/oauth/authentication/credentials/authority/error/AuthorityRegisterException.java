package cube8540.oauth.authentication.credentials.authority.error;

public class AuthorityRegisterException extends RuntimeException {

    private String code;
    private String description;

    private AuthorityRegisterException(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public static AuthorityRegisterException alreadyExistsId(String description) {
        return new AuthorityRegisterException(AuthorityErrorCodes.ALREADY_EXISTS_ID, description);
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}
