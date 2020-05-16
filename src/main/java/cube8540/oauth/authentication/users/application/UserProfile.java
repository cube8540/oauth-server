package cube8540.oauth.authentication.users.application;

import cube8540.oauth.authentication.users.domain.User;
import lombok.Value;

import java.time.LocalDateTime;

@Value
public class UserProfile {

    private String username;

    private String email;

    private LocalDateTime registeredAt;

    public static UserProfile of(User user) {
        return new UserProfile(user.getUsername().getValue(), user.getEmail().getValue(), user.getRegisteredAt());
    }
}
