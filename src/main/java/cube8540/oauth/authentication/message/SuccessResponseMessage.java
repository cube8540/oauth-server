package cube8540.oauth.authentication.message;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
public class SuccessResponseMessage<T> extends ResponseMessage {

    private final T data;

    private SuccessResponseMessage(HttpStatus status, T data) {
        super(status);
        this.data = data;
    }

    public static <T> SuccessResponseMessage<T> ok(T data) {
        return new SuccessResponseMessage<>(HttpStatus.OK, data);
    }

    public static <T> SuccessResponseMessage<T> created(T data) {
        return new SuccessResponseMessage<>(HttpStatus.CREATED, data);
    }
}
