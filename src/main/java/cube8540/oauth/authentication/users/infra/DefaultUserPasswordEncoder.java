package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.UserPassword;
import cube8540.oauth.authentication.users.domain.UserPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class DefaultUserPasswordEncoder implements UserPasswordEncoder {

    private final PasswordEncoder encoder;

    public DefaultUserPasswordEncoder(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public boolean matches(UserPassword encryptedPassword, UserPassword rawPassword) {
        return matches(rawPassword.getPassword(), encryptedPassword.getPassword());
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        return encoder.upgradeEncoding(encodedPassword);
    }
}
