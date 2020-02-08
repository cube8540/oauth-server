package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.Embeddable;
import javax.persistence.Transient;
import java.io.Serializable;
import java.time.Clock;
import java.time.LocalDateTime;

@Getter
@ToString
@EqualsAndHashCode
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Embeddable
public class UserCredentialsKey implements Serializable {

    @Transient
    @Setter(AccessLevel.PROTECTED)
    private static Clock clock = Clock.system(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());

    private String keyValue;

    private LocalDateTime expiryDateTime;

    public UserCredentialsKey(String keyValue) {
        this.keyValue = keyValue;
        this.expiryDateTime = LocalDateTime.now(clock).plusMinutes(5);
    }

    public UserKeyMatchedResult matches(String key) {
        if (LocalDateTime.now(clock).isAfter(expiryDateTime)) {
            return UserKeyMatchedResult.EXPIRED;
        } else if (keyValue.equals(key)) {
            return UserKeyMatchedResult.MATCHED;
        } else {
            return UserKeyMatchedResult.NOT_MATCHED;
        }
    }
}
