package cube8540.oauth.authentication.users.domain;

import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.io.Serializable;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ToString
@EqualsAndHashCode
public class UserRawPassword implements UserPassword, Serializable {

    private static final String REQUIRED_PATTERN_VALUE = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{12,30}$";
    private static final String WHITELIST_PATTERN_VALUE = "^[#?!@$%^&*\\-a-zA-Z0-9 ]+$";

    private String password;

    public UserRawPassword(String password) {
        this.password = password;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public boolean isValid() {
        return matchesPattern(REQUIRED_PATTERN_VALUE) && matchesPattern(WHITELIST_PATTERN_VALUE);
    }

    @Override
    public UserPassword encrypted(UserPasswordEncoder encoder) {
        return new UserEncryptedPassword(encoder.encode(password));
    }

    private boolean matchesPattern(String pattern) {
        return Optional.ofNullable(password)
                .map(password -> Pattern.compile(pattern).matcher(password))
                .map(Matcher::matches)
                .orElse(false);
    }
}
