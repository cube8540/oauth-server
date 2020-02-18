package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("유저 계정 테스트")
class UserTest {

    private static final String RAW_EMAIL = "email@email.com";

    private static final String PASSWORD = "Password1234!@#$";
    private static final String CHANGE_PASSWORD = "ChangePassword1234!@#$";
    private static final String ENCRYPTED_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";
    private static final String CHANGE_ENCRYPTED_PASSWORD = "$2y$10$zMSWRQlgsLcgzD4OuId7l.T2OlqDtpayXbyqWuXIJ7R3BmKC26Bju";

    private PasswordEncoder encoder;
    private UserCredentialsKeyGenerator keyGenerator;

    private User user;

    @BeforeEach
    void setup() {
        this.encoder = mock(PasswordEncoder.class);
        this.keyGenerator = mock(UserCredentialsKeyGenerator.class);
        this.user = new User(RAW_EMAIL, PASSWORD);

        when(encoder.encode(PASSWORD)).thenReturn(ENCRYPTED_PASSWORD);
        when(encoder.matches(PASSWORD, ENCRYPTED_PASSWORD)).thenReturn(Boolean.TRUE);
        when(encoder.encode(CHANGE_PASSWORD)).thenReturn(CHANGE_ENCRYPTED_PASSWORD);
        when(encoder.matches(CHANGE_PASSWORD, CHANGE_ENCRYPTED_PASSWORD)).thenReturn(Boolean.TRUE);
    }

    @Nested
    @DisplayName("유효성 검사")
    class Validation {

        private UserValidationPolicy policy;

        ValidationRule<User> emailValidation;
        ValidationRule<User> passwordValidation;

        @BeforeEach
        @SuppressWarnings("unchecked")
        void setup() {
            this.policy = mock(UserValidationPolicy.class);
            this.emailValidation = mock(ValidationRule.class);
            this.passwordValidation = mock(ValidationRule.class);

            when(policy.emailRule()).thenReturn(emailValidation);
            when(policy.passwordRule()).thenReturn(passwordValidation);
        }

        @Nested
        @DisplayName("허용된 이메일이 아닐시")
        class WhenUserEmailNotAllowed {
            private ValidationError emailError;

            @BeforeEach
            void setup() {
                this.emailError = new ValidationError("EMAIL", "INVALID EMAIL");

                when(emailValidation.isValid(user)).thenReturn(false);
                when(emailValidation.error()).thenReturn(emailError);
                when(passwordValidation.isValid(user)).thenReturn(true);
            }

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> user.validation(policy));
            }

            @Test
            @DisplayName("이메일 유효성에 관련된 에러가 포함되어 있어야 한다.")
            void shouldContainsEmailErrorMessage() {
                UserInvalidException exception = assertThrows(UserInvalidException.class, () -> user.validation(policy));

                assertTrue(exception.getErrors().contains(emailError));
            }
        }

        @Nested
        @DisplayName("허용된 패스워드가 아닐시")
        class WhenUserPasswordNotAllowed {
            private ValidationError passwordError;

            @BeforeEach
            void setup() {
                this.passwordError = new ValidationError("PASSWORD", "INVALID PASSWORD");

                when(emailValidation.isValid(user)).thenReturn(true);
                when(passwordValidation.isValid(user)).thenReturn(false);
                when(passwordValidation.error()).thenReturn(passwordError);
            }

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> user.validation(policy));
            }

            @Test
            @DisplayName("패스워드 유효성 관련된 에러가 포함되어 있어야 한다.")
            void shouldContainsPasswordErrorMessage() {
                UserInvalidException exception = assertThrows(UserInvalidException.class, () -> user.validation(policy));

                assertTrue(exception.getErrors().contains(passwordError));
            }
        }
    }

    @Nested
    @DisplayName("패스워드 변경")
    class ChangePassword {

        @Nested
        @DisplayName("이전에 사용하던 패스워드와 일치하지 않을시")
        class WhenNotMatchedExistingPassword {

            @BeforeEach
            void setup() {
                when(encoder.matches(PASSWORD, PASSWORD)).thenReturn(false);
            }

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class,
                        () -> user.changePassword(PASSWORD, CHANGE_PASSWORD, encoder));
            }
        }

        @Nested
        @DisplayName("이전에 사용하던 패스워드가 일치할시")
        class WhenExistingPasswordMatched {

            @BeforeEach
            void setup() {
                when(encoder.matches(PASSWORD, PASSWORD)).thenReturn(true);
            }

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 저장하여야 한다.")
            void shouldSaveGivenPassword() {
                user.changePassword(PASSWORD, CHANGE_PASSWORD, encoder);
                assertEquals(CHANGE_PASSWORD, user.getPassword());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 분실")
    class ForgotPassword {
        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);

            when(keyGenerator.generateKey()).thenReturn(key);
        }

        @Test
        @DisplayName("키 생성기에서 반환된 키를 저장해야 한다.")
        void shouldSaveCreatedKeyByGivenGenerator() {
            user.forgotPassword(keyGenerator);
            assertEquals(key, user.getPasswordCredentialsKey());
        }
    }

    @Nested
    @DisplayName("패스워드 초기화")
    class ResetPassword {

        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);

            when(keyGenerator.generateKey()).thenReturn(key);
        }

        @Nested
        @DisplayName("패스워드 인증키가 할당되지 않았을시")
        class WhenKeyNotGenerated {

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class, () -> user.resetPassword("KEY", CHANGE_PASSWORD));
            }
        }

        @Nested
        @DisplayName("키가 매칭되지 않을시")
        class WhenKeyNotMatched {

            @BeforeEach
            void setup() {
                user.forgotPassword(keyGenerator);

                when(key.matches(any())).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
            }

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class, () -> user.resetPassword("KEY", CHANGE_PASSWORD));
            }
        }

        @Nested
        @DisplayName("키가 만료되었을시")
        class WhenKeyExpired {

            @BeforeEach
            void setup() {
                user.forgotPassword(keyGenerator);

                when(key.matches(any())).thenReturn(UserKeyMatchedResult.EXPIRED);
            }

            @Test
            @DisplayName("UserExpiredException이 발생해야 한다.")
            void shouldThrowsUserExpiredException() {
                assertThrows(UserExpiredException.class, () -> user.resetPassword("KEY", CHANGE_PASSWORD));
            }
        }

        @Nested
        @DisplayName("패스워드 인증키가 옳바를시")
        class WhenKeyMatched {

            private String matchedKey = "KEY";

            @BeforeEach
            void setup() {
                user.forgotPassword(keyGenerator);

                when(key.matches(matchedKey)).thenReturn(UserKeyMatchedResult.MATCHED);
            }

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 저장하여야 한다.")
            void shouldSaveGivenPassword() {
                user.resetPassword(matchedKey, CHANGE_PASSWORD);
                assertEquals(CHANGE_PASSWORD, user.getPassword());
            }

            @Test
            @DisplayName("패스워드 인증키를 null로 변경한다.")
            void shouldPasswordCredentialsKeySetNull() {
                user.resetPassword(matchedKey, CHANGE_PASSWORD);
                assertNull(user.getPasswordCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("계정 인증키 할당")
    class GeneratedCredentialsKey {

        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);

            when(keyGenerator.generateKey()).thenReturn(key);
        }

        @Nested
        @DisplayName("인증받지 않은 계정일시")
        class WhenNotCredentialsAccount {

            @Test
            @DisplayName("키 생성기에서 반환된 키를 저장해야 한다.")
            void shouldSaveCreatedKeyByGivenGenerator() {
                user.generateCredentialsKey(keyGenerator);
                assertEquals(key, user.getCredentialsKey());
            }
        }

        @Nested
        @DisplayName("이미 인증 받은 계정일시")
        class WhenAlreadyCertificationAccount {

            @BeforeEach
            void setup() {
                when(key.matches(any())).thenReturn(UserKeyMatchedResult.MATCHED);

                Collection<AuthorityCode> authorityCodes = new HashSet<>(Arrays.asList(
                        new AuthorityCode("CODE1"),
                        new AuthorityCode("CODE2"),
                        new AuthorityCode("CODE3")));
                user.generateCredentialsKey(keyGenerator);
                user.credentials("KEY", authorityCodes);
            }

            @Test
            @DisplayName("UserCertificationException이 발생해야 한다.")
            void shouldThrowsUserCertificationException() {
                assertThrows(UserAlreadyCertificationException.class, () -> user.generateCredentialsKey(keyGenerator));
            }
        }

        @Nested
        @DisplayName("이미 인증 받았지만 할당된 권한이 없을시")
        class WhenAlreadyCertificationNotHaveAuthoritiesAccount {

            @BeforeEach
            void setup() {
                when(key.matches(any())).thenReturn(UserKeyMatchedResult.MATCHED);

                user.generateCredentialsKey(keyGenerator);
                user.credentials("KEY", Collections.emptySet());
            }

            @Test
            @DisplayName("키 생성기에서 반환된 키를 저장해야 한다.")
            void shouldSaveCreatedKeyByGivenGenerator() {
                user.generateCredentialsKey(keyGenerator);
                assertEquals(key, user.getCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("계정 인증")
    class CredentialsAccount {

        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);
        }

        @Nested
        @DisplayName("인증키가 할당되지 않았을시")
        class WhenKeyNotGenerated {

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class, () -> user.credentials("KEY", Collections.emptyList()));
            }
        }

        @Nested
        @DisplayName("인증키가 매칭되지 않을시")
        class WhenKeyNotMatched {

            @BeforeEach
            void setup() {
                when(key.matches(any())).thenReturn(UserKeyMatchedResult.NOT_MATCHED);
                when(keyGenerator.generateKey()).thenReturn(key);
                user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class, () -> user.credentials("KEY", Collections.emptyList()));
            }
        }

        @Nested
        @DisplayName("인증키가 만료되었을시")
        class WhenKeyExpired {

            @BeforeEach
            void setup() {
                when(key.matches(any())).thenReturn(UserKeyMatchedResult.EXPIRED);
                when(keyGenerator.generateKey()).thenReturn(key);

                user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("UserExpiredException이 발생해야 한다.")
            void shouldThrowsUserExpiredException() {
                assertThrows(UserExpiredException.class, () -> user.credentials("KEY", Collections.emptyList()));
            }
        }

        @Nested
        @DisplayName("인증키가 매칭될시")
        class WhenKeyMatched {
            private String matchedKey = "KEY";
            private Collection<AuthorityCode> authorityCodes;

            @BeforeEach
            void setup() {
                when(key.matches(matchedKey)).thenReturn(UserKeyMatchedResult.MATCHED);
                when(keyGenerator.generateKey()).thenReturn(key);

                this.authorityCodes = new HashSet<>(Arrays.asList(
                        new AuthorityCode("CODE1"),
                        new AuthorityCode("CODE2"),
                        new AuthorityCode("CODE3")));
                user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("인자로 받은 권한을 저장해야한다.")
            void shouldSaveGivenAuthorities() {
                user.credentials(matchedKey, authorityCodes);
                assertEquals(authorityCodes, user.getAuthorities());
            }

            @Test
            @DisplayName("인증키를 null로 설정해야 한다.")
            void shouldCredentialsKeySetNull() {
                user.credentials(matchedKey, authorityCodes);
                assertNull(user.getCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 암호화")
    class PasswordEncrypting {

        @Test
        @DisplayName("패스워드를 암호화하여 저장해야 한다.")
        void shouldSaveEncryptedPassword() {
            user.encrypted(encoder);

            assertEquals(ENCRYPTED_PASSWORD, user.getPassword());
        }
    }
}