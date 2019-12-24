package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.users.domain.event.UserCreatedEvent;
import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
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

        assertValidation();
        encrypted(encoder);
        registerEvent(new UserCreatedEvent(this.email));
    }

    private void encrypted(UserPasswordEncoder encoder) {
        this.password = this.password.encrypted(encoder);
    }

    private void assertValidation() {
        Validator.of(this).registerRule(new UserEmailValidationRule())
                .registerRule(new UserPasswordValidationRule())
                .getResult().hasErrorThrows(UserInvalidException::new);
    }
}
