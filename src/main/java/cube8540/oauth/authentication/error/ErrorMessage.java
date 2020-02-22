package cube8540.oauth.authentication.error;

import lombok.Value;

import java.io.Serializable;

@Value
public class ErrorMessage<T> implements Serializable {

    private String errorCode;

    private T description;

    public static <T> ErrorMessage<T> instance(String errorCode, T description) {
        return new ErrorMessage<>(errorCode, description);
    }
}
