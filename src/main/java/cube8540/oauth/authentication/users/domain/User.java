package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.users.domain.event.UserCreatedEvent;
import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
import cube8540.oauth.authentication.users.domain.exception.UserNotMatchedException;
import cube8540.oauth.authentication.users.domain.validator.UserEmailValidationRule;
import cube8540.oauth.authentication.users.domain.validator.UserPasswordValidationRule;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends AbstractAggregateRoot<User> {

    private UserEmail email;

    private UserPassword password;

    public User(String email, String password, UserPasswordEncoder encoder) {
        this.email = new UserEmail(email);
        this.password = new UserRawPassword(password);

        Validator.of(this).registerRule(new UserEmailValidationRule())
                .registerRule(new UserPasswordValidationRule())
                .getResult().hasErrorThrows(UserInvalidException::new);
        encrypted(encoder);
        registerEvent(new UserCreatedEvent(this.email));
    }

    public void changePassword(String existsPassword, String changePassword, UserPasswordEncoder encoder) {
        if (!encoder.matches(password, new UserRawPassword(existsPassword))) {
            throw new UserNotMatchedException("existing password is not matched");
        }
        changePassword(changePassword, encoder);
    }

    private void changePassword(String changePassword, UserPasswordEncoder encoder) {
        this.password = new UserRawPassword(changePassword);
        Validator.of(this).registerRule(new UserPasswordValidationRule())
                .getResult().hasErrorThrows(UserInvalidException::new);
        encrypted(encoder);
    }

    private void encrypted(UserPasswordEncoder encoder) {
        this.password = this.password.encrypted(encoder);
    }
}
