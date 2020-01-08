package cube8540.oauth.authentication.users.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.persistence.Embeddable;
import java.io.Serializable;

@ToString
@EqualsAndHashCode
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Embeddable
class UserEncryptedPassword implements UserPassword, Serializable {

    private String password;

    protected UserEncryptedPassword(String password) {
        this.password = password;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isEncrypted() {
        return true;
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public UserPassword encrypted(UserPasswordEncoder encoder) {
        return new UserEncryptedPassword(encoder.encode(password));
    }
}
