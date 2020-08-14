package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import cube8540.validator.core.Validator;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserTestHelper {

    static final String RAW_USERNAME = "username1234";

    static final String RAW_EMAIL = "email@email.com";

    static final String PASSWORD = "Password1234!@#$";
    static final String CHANGE_PASSWORD = "ChangePassword123$!@#$";
    static final String ENCRYPTED_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    static final String RAW_CREDENTIALS_KEY = "CREDENTIALS-KEY";
    static final String RAW_PASSWORD_CREDENTIALS_KEY = "PASSWORD-CREDENTIALS-KEY";

    static final String ERROR_PROPERTY = "property";
    static final String ERROR_MESSAGE = "message";

    static final LocalDateTime NOW = LocalDateTime.of(2020, 2, 8, 23, 5);
    static final LocalDateTime EXPIRATION_DATETIME = NOW.plusMinutes(5);
    static final LocalDateTime NOT_EXPIRATION_DATETIME = EXPIRATION_DATETIME.plusMinutes(1);

    static Clock makeDefaultClock() {
        return Clock.fixed(NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    }

    static Clock makeExpiredClock() {
        return Clock.fixed(NOT_EXPIRATION_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    }

    @SuppressWarnings("unchecked")
    static UserValidatorFactory makeErrorValidatorFactory(User user) {
        ValidationRule<User> validationRule = mock(ValidationRule.class);
        UserValidatorFactory factory = mock(UserValidatorFactory.class);

        when(validationRule.isValid(user)).thenReturn(false);
        when(validationRule.error()).thenReturn(new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE));

        Validator<User> validator = Validator.of(user)
                .registerRule(validationRule);
        when(factory.createValidator(user)).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static UserValidatorFactory makePassValidatorFactory(User user) {
        ValidationRule<User> validationRule = mock(ValidationRule.class);
        UserValidatorFactory factory = mock(UserValidatorFactory.class);

        when(validationRule.isValid(user)).thenReturn(true);

        Validator<User> validator = Validator.of(user)
                .registerRule(validationRule);
        when(factory.createValidator(user)).thenReturn(validator);

        return factory;
    }

    static PasswordEncoder makePasswordEncoder(String rawPassword, String encodedPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(encoder.matches(rawPassword, encodedPassword)).thenReturn(true);

        return encoder;
    }

    static PasswordEncoder makeMismatchesEncoder(String rawPassword, String encodedPassword) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.matches(rawPassword, encodedPassword)).thenReturn(false);

        return encoder;
    }

    static UserCredentialsKey makeMismatchedKey() {
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(anyString())).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
        return key;
    }

    static UserCredentialsKey makeExpiredKey() {
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(anyString())).thenReturn(UserKeyMatchedResult.EXPIRED);
        return key;
    }

    static UserCredentialsKey makeCredentialsKey(String credentialsKey) {
        UserCredentialsKey key = mock(UserCredentialsKey.class);

        when(key.matches(credentialsKey)).thenReturn(UserKeyMatchedResult.MATCHED);
        return key;
    }

    static UserCredentialsKeyGenerator makeKeyGenerator(UserCredentialsKey credentialsKey) {
        UserCredentialsKeyGenerator keyGenerator = mock(UserCredentialsKeyGenerator.class);

        when(keyGenerator.generateKey()).thenReturn(credentialsKey);
        return keyGenerator;
    }

}
