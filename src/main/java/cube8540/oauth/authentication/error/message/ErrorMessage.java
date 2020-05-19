package cube8540.oauth.authentication.error.message;

import lombok.Value;

import java.io.Serializable;

@Value
public class ErrorMessage<T> implements Serializable {

    public static final ErrorMessage<Object> ACCESS_DENIED_ERROR = ErrorMessage.instance(ErrorCodes.ACCESS_DENIED, "access denied");

    public static final ErrorMessage<Object> UNKNOWN_SERVER_ERROR = ErrorMessage.instance(ErrorCodes.SERVER_ERROR, "unknown server error");

    String errorCode;

    T description;

    public static <T> ErrorMessage<T> instance(String errorCode, T description) {
        return new ErrorMessage<>(errorCode, description);
    }
}
