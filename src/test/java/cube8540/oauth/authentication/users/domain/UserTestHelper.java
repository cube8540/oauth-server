package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
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

    static final String USERNAME_ERROR_PROPERTY = "username";
    static final String USERNAME_ERROR_MESSAGE = "message";

    static final String EMAIL_ERROR_PROPERTY = "email";
    static final String EMAIL_ERROR_MESSAGE = "message";

    static final String PASSWORD_ERROR_PROPERTY = "password";
    static final String PASSWORD_ERROR_MESSAGE = "message";

    static final LocalDateTime NOW = LocalDateTime.of(2020, 2, 8, 23, 5);
    static final LocalDateTime EXPIRATION_DATETIME = NOW.plusMinutes(5);
    static final LocalDateTime NOT_EXPIRATION_DATETIME = EXPIRATION_DATETIME.plusMinutes(1);

    static final String RAW_AUTHORITY = "AUTHORITY";
    static final UserAuthority AUTHORITY = new UserAuthority(RAW_AUTHORITY);

    static Clock makeDefaultClock() {
        return Clock.fixed(NOW.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    }

    static Clock makeExpiredClock() {
        return Clock.fixed(NOT_EXPIRATION_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<User> makePassValidationRule(User user) {
        ValidationRule<User> validationRule = mock(ValidationRule.class);

        when(validationRule.isValid(user)).thenReturn(true);

        return validationRule;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<User> makeErrorValidationRule(User user, ValidationError error) {
        ValidationRule<User> validationRule = mock(ValidationRule.class);

        when(validationRule.isValid(user)).thenReturn(false);
        when(validationRule.error()).thenReturn(error);

        return validationRule;
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

    static MockValidationPolicy makeValidationPolicy() {
        return new MockValidationPolicy();
    }

    static final class MockValidationPolicy {
        private UserValidationPolicy policy;

        private MockValidationPolicy() {
            this.policy = mock(UserValidationPolicy.class);
        }

        MockValidationPolicy usernameRule(ValidationRule<User> validationRule) {
            when(this.policy.usernameRule()).thenReturn(validationRule);
            return this;
        }

        MockValidationPolicy emailRule(ValidationRule<User> validationRule) {
            when(this.policy.emailRule()).thenReturn(validationRule);
            return this;
        }

        MockValidationPolicy passwordRule(ValidationRule<User> validationRule) {
            when(this.policy.passwordRule()).thenReturn(validationRule);
            return this;
        }

        UserValidationPolicy build() {
            return policy;
        }
    }

}
