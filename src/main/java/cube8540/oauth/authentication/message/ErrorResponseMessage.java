package cube8540.oauth.authentication.message;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

import java.util.Collection;
import java.util.Collections;

@Getter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class ErrorResponseMessage<T> extends ResponseMessage {

    private Collection<T> errors;

    private ErrorResponseMessage(HttpStatus status, Collection<T> errors) {
        super(status);
        this.errors = errors;
    }

    private ErrorResponseMessage(HttpStatus status, T errors) {
        this(status, Collections.singleton(errors));
    }

    public static <T> ErrorResponseMessage<T> badRequest(Collection<T> errors) {
        return new ErrorResponseMessage<>(HttpStatus.BAD_REQUEST, errors);
    }

    public static <T> ErrorResponseMessage<T> badRequest(T cause) {
        return new ErrorResponseMessage<>(HttpStatus.BAD_REQUEST, cause);
    }

    public static <T> ErrorResponseMessage<T> conflict(Collection<T> errors) {
        return new ErrorResponseMessage<>(HttpStatus.CONFLICT, errors);
    }

    public static <T> ErrorResponseMessage<T> conflict(T cause) {
        return new ErrorResponseMessage<>(HttpStatus.CONFLICT, cause);
    }

    public static <T> ErrorResponseMessage<T> gone(Collection<T> errors) {
        return new ErrorResponseMessage<>(HttpStatus.GONE, errors);
    }

    public static <T> ErrorResponseMessage<T> gone(T cause) {
        return new ErrorResponseMessage<>(HttpStatus.GONE, cause);
    }

    public static <T> ErrorResponseMessage<T> notfound(Collection<T> errors) {
        return new ErrorResponseMessage<>(HttpStatus.NOT_FOUND, errors);
    }

    public static <T> ErrorResponseMessage<T> notfound(T cause) {
        return new ErrorResponseMessage<>(HttpStatus.NOT_FOUND, cause);
    }

    public static <T> ErrorResponseMessage<T> forbidden(Collection<T> errors) {
        return new ErrorResponseMessage<>(HttpStatus.FORBIDDEN, errors);
    }

    public static <T> ErrorResponseMessage<T> forbidden(T cause) {
        return new ErrorResponseMessage<>(HttpStatus.FORBIDDEN, cause);
    }
}