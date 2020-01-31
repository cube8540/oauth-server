package cube8540.oauth.authentication.users.domain;

import org.springframework.security.crypto.password.PasswordEncoder;

public interface UserPasswordEncoder extends PasswordEncoder {

    boolean matches(UserPassword encryptedPassword, UserPassword rawPassword);

}
