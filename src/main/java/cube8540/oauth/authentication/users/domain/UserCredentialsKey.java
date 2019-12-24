package cube8540.oauth.authentication.users.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@ToString
@EqualsAndHashCode
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserCredentialsKey implements Serializable {

    private String keyValue;

    private LocalDateTime expiryDateTime;

    public UserKeyMatchedResult matches(String key) {
        if (LocalDateTime.now().isAfter(expiryDateTime)) {
            return UserKeyMatchedResult.EXPIRED;
        } else if (keyValue.equals(key)) {
            return UserKeyMatchedResult.MATCHED;
        } else {
            return UserKeyMatchedResult.NOT_MATCHED;
        }
    }
}
