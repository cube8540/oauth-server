package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.time.LocalDateTime;

@Value
@AllArgsConstructor
public class UserProfile {

    private String email;

    private LocalDateTime registeredAt;

    public UserProfile(User user) {
        this.email = user.getEmail().getValue();
        this.registeredAt = user.getRegisteredAt();
    }
}
