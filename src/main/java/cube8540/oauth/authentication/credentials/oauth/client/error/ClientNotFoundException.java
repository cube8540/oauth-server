package cube8540.oauth.authentication.credentials.oauth.client.error;

import lombok.Getter;

@Getter
public class ClientNotFoundException extends RuntimeException {

    private String code;
    private String description;

    public ClientNotFoundException(String description) {
        this.code = ClientErrorCodes.NOT_FOUND;
        this.description = description;
    }
}
