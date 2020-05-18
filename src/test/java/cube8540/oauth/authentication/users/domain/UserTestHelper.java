package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

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

    static MockPasswordEncoder mockPasswordEncoder() {
        return new MockPasswordEncoder();
    }

    static MockCredentialsKey mockCredentialsKey() {
        return new MockCredentialsKey();
    }

    static UserCredentialsKeyGenerator mockKeyGenerator(UserCredentialsKey credentialsKey) {
        UserCredentialsKeyGenerator keyGenerator = mock(UserCredentialsKeyGenerator.class);

        when(keyGenerator.generateKey()).thenReturn(credentialsKey);
        return keyGenerator;
    }

    static MockValidationRule<User> mockValidationRule() {
        return new MockValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static final class MockPasswordEncoder {
        private PasswordEncoder encoder;

        private MockPasswordEncoder() {
            this.encoder = mock(PasswordEncoder.class);
        }

        MockPasswordEncoder encode() {
            when(this.encoder.encode(PASSWORD)).thenReturn(ENCRYPTED_PASSWORD);
            return this;
        }

        MockPasswordEncoder matches() {
            when(this.encoder.matches(PASSWORD, PASSWORD)).thenReturn(true);
            return this;
        }

        MockPasswordEncoder mismatches() {
            when(this.encoder.matches(PASSWORD, PASSWORD)).thenReturn(false);
            return this;
        }

        PasswordEncoder build() {
            return encoder;
        }
    }

    static final class MockCredentialsKey {
        private UserCredentialsKey key;

        private MockCredentialsKey() {
            this.key = mock(UserCredentialsKey.class);
        }

        MockCredentialsKey key(String key) {
            when(this.key.getKeyValue()).thenReturn(key);
            return this;
        }

        MockCredentialsKey matches(String key) {
            when(this.key.matches(key)).thenReturn(UserKeyMatchedResult.MATCHED);
            return this;
        }

        MockCredentialsKey mismatches(String key) {
            when(this.key.matches(key)).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
            return this;
        }

        MockCredentialsKey expired(String key) {
            when(this.key.matches(key)).thenReturn(UserKeyMatchedResult.EXPIRED);
            return this;
        }

        UserCredentialsKey build() {
            return key;
        }
    }

    static final class MockValidationRule<T> {
        private ValidationRule<T> rule;

        @SuppressWarnings("unchecked")
        private MockValidationRule() {
            this.rule = mock(ValidationRule.class);
        }

        MockValidationRule<T> configReturnTrue(T target) {
            when(this.rule.isValid(target)).thenReturn(true);
            return this;
        }

        MockValidationRule<T> configReturnFalse(T target) {
            when(this.rule.isValid(target)).thenReturn(false);
            return this;
        }

        MockValidationRule<T> validationError(ValidationError error) {
            when(this.rule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return rule;
        }
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
