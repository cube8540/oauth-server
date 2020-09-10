package cube8540.oauth.authentication.error;

import lombok.Getter;

@Getter
public class ServiceException extends RuntimeException {

    private final String code;

    public ServiceException(String code, String message) {
        super(message);
        this.code = code;
    }
}
