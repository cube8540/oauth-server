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

    private String keyValue;

    private LocalDateTime expiryDateTime;

    @Transient
    @Setter(AccessLevel.PROTECTED)
    private Clock clock = Clock.system(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());

    public UserCredentialsKey(String keyValue, LocalDateTime expiryDateTime) {
        this.keyValue = keyValue;
        this.expiryDateTime = expiryDateTime;
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
