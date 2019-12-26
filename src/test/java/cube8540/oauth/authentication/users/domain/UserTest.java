package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.users.domain.exception.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.exception.UserExpiredException;
import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
import cube8540.oauth.authentication.users.domain.exception.UserNotMatchedException;
import cube8540.oauth.authentication.users.domain.validator.UserEmailValidationRule;
import cube8540.oauth.authentication.users.domain.validator.UserPasswordValidationRule;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

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
    private static final String NOT_ALLOWED_RAW_EMAIL = "email";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_PASSWORD = "Password1234!@#$";
    private static final String RAW_CHANGE_PASSWORD = "ChangePassword1234!@#$";
    private static final String NOT_ALLOWED_RAW_PASSWORD = "password";
    private static final String RAW_ENCRYPTED_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";
    private static final String RAW_CHANGE_ENCRYPTED_PASSWORD = "$2y$10$zMSWRQlgsLcgzD4OuId7l.T2OlqDtpayXbyqWuXIJ7R3BmKC26Bju";
    private static final UserPassword PASSWORD = new UserRawPassword(RAW_PASSWORD);
    private static final UserPassword CHANGE_PASSWORD = new UserRawPassword(RAW_CHANGE_PASSWORD);
    private static final UserPassword ENCRYPTED_PASSWORD = new UserEncryptedPassword(RAW_ENCRYPTED_PASSWORD);
    private static final UserPassword CHANGE_ENCRYPTED_PASSWORD =  new UserEncryptedPassword(RAW_CHANGE_ENCRYPTED_PASSWORD);

    private UserPasswordEncoder encoder;
    private UserCredentialsKeyGenerator keyGenerator;

    @BeforeEach
    void setup() {
        this.encoder = mock(UserPasswordEncoder.class);
        this.keyGenerator = mock(UserCredentialsKeyGenerator.class);

        when(encoder.encoding(RAW_PASSWORD)).thenReturn(RAW_ENCRYPTED_PASSWORD);
        when(encoder.matches(ENCRYPTED_PASSWORD, PASSWORD)).thenReturn(Boolean.TRUE);
        when(encoder.encoding(RAW_CHANGE_PASSWORD)).thenReturn(RAW_CHANGE_ENCRYPTED_PASSWORD);
        when(encoder.matches(CHANGE_ENCRYPTED_PASSWORD, CHANGE_PASSWORD)).thenReturn(Boolean.TRUE);
    }

    @Nested
    @DisplayName("유저 계정 생성")
    class InitializeUser {

        @Nested
        @DisplayName("허용되지 않은 이메일로 유저를 생성시")
        class WhenCreateWithNotAllowedEmail {

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> new User(NOT_ALLOWED_RAW_EMAIL, RAW_PASSWORD, encoder));
            }

            @Test
            @DisplayName("이메일 관련된 에러가 포함되어야 한다.")
            void shouldContainsEmailErrorMessage() {
                ValidationError emailErrors = new ValidationError(UserEmailValidationRule.PROPERTY, UserEmailValidationRule.MESSAGE);
                UserInvalidException exception = assertThrows(UserInvalidException.class, () -> new User(NOT_ALLOWED_RAW_EMAIL, RAW_PASSWORD, encoder));

                assertTrue(exception.getErrors().contains(emailErrors));
            }
        }

        @Nested
        @DisplayName("허용되지 않은 패스워드로 유저 생성시")
        class WhenCreateWithNotAllowedPassword {

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> new User(RAW_EMAIL, NOT_ALLOWED_RAW_PASSWORD, encoder));
            }

            @Test
            @DisplayName("패스워드 관련된 에러가 포함되어야 한다.")
            void shouldContainsPasswordErrorMessage() {
                ValidationError passwordErrors = new ValidationError(UserPasswordValidationRule.PROPERTY, UserPasswordValidationRule.MESSAGE);
                UserInvalidException exception = assertThrows(UserInvalidException.class, () -> new User(RAW_EMAIL, NOT_ALLOWED_RAW_PASSWORD, encoder));

                assertTrue(exception.getErrors().contains(passwordErrors));
            }
        }

        @Nested
        @DisplayName("허용되는 매개변수로 유저 생성시")
        class WhenCreateWithAllowedArgs {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);
            }

            @Test
            @DisplayName("생성자에서 받은 이메일을 저장해야 한다.")
            void shouldSaveGiveConstructorEmail() {
                assertEquals(EMAIL, user.getEmail());
            }

            @Test
            @DisplayName("생성자에서 받은 패스워드를 암호화 하여 저장해야 한다.")
            void shouldSaveGivePasswordEncrypting() {
                assertEquals(ENCRYPTED_PASSWORD, user.getPassword());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 변경")
    class ChangePassword {

        private User user;

        @BeforeEach
        void setup() {
            this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);
        }

        @Nested
        @DisplayName("유효하지 않은 패스워드로 변경시")
        class WhenNotAllowedPassword {

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> user.changePassword(RAW_PASSWORD, NOT_ALLOWED_RAW_PASSWORD, encoder));
            }

            @Test
            @DisplayName("패스워드 관련 에러가 포함되어야 한다.")
            void shouldContainsPasswordErrorMessage() {
                UserInvalidException exception = assertThrows(UserInvalidException.class,
                        () -> user.changePassword(RAW_PASSWORD, NOT_ALLOWED_RAW_PASSWORD, encoder));
                ValidationError passwordError = new ValidationError(UserPasswordValidationRule.PROPERTY, UserPasswordValidationRule.MESSAGE);
                assertTrue(exception.getErrors().contains(passwordError));
            }
        }

        @Nested
        @DisplayName("이전에 사용하던 패스워드와 일치하지 않을시")
        class WhenNotMatchedExistingPassword {

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class,
                        () -> user.changePassword("NOT MATCHED PASSWORD 1", RAW_CHANGE_PASSWORD, encoder));
                assertThrows(UserNotMatchedException.class,
                        () -> user.changePassword("NOT MATCHED PASSWORD 2", RAW_CHANGE_PASSWORD, encoder));
            }
        }

        @Nested
        @DisplayName("이전에 사용하던 패스워드가 일치하며, 유효한 패스워드로 패스워드 변경시")
        class WhenExistingPasswordMatchedAndAllowedPassword {

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 암호화 하여 저장하여야 한다.")
            void shouldSaveGivenPasswordEncrypted() {
                user.changePassword(RAW_PASSWORD, RAW_CHANGE_PASSWORD, encoder);
                assertEquals(CHANGE_ENCRYPTED_PASSWORD, user.getPassword());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 분실")
    class ForgotPassword {

        private User user;
        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);
            this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);

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

        private User user;
        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);
            this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);

            when(keyGenerator.generateKey()).thenReturn(key);
        }

        @Nested
        @DisplayName("패스워드 인증키가 할당되지 않았을시")
        class WhenKeyNotGenerated {

            @Test
            @DisplayName("UserNotMatchedException이 발생해야 한다.")
            void shouldThrowsUserNotMatchedException() {
                assertThrows(UserNotMatchedException.class, () -> user.resetPassword("KEY", RAW_CHANGE_PASSWORD, encoder));
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
                assertThrows(UserNotMatchedException.class, () -> user.resetPassword("KEY", RAW_CHANGE_PASSWORD, encoder));
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
                assertThrows(UserExpiredException.class, () -> user.resetPassword("KEY", RAW_CHANGE_PASSWORD, encoder));
            }
        }

        @Nested
        @DisplayName("변경할 패스워드가 유효하지 않을시")
        class WhenNotAllowedPassword {

            private String matchedKey = "KEY";

            @BeforeEach
            void setup() {
                user.forgotPassword(keyGenerator);

                when(key.matches(matchedKey)).thenReturn(UserKeyMatchedResult.MATCHED);
            }

            @Test
            @DisplayName("UserInvalidException이 발생해야 한다.")
            void shouldThrowsUserInvalidException() {
                assertThrows(UserInvalidException.class, () -> user.resetPassword(matchedKey, NOT_ALLOWED_RAW_PASSWORD, encoder));
            }
        }

        @Nested
        @DisplayName("키가 매칭되며 변경될 패스워드가 유효할시")
        class WhenKeyMatchedAndAllowedPassword {

            private String matchedKey = "KEY";

            @BeforeEach
            void setup() {
                user.forgotPassword(keyGenerator);

                when(key.matches(matchedKey)).thenReturn(UserKeyMatchedResult.MATCHED);
            }

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 암호화 하여 저장하여야 한다.")
            void shouldSaveGivenPasswordEncrypted() {
                user.resetPassword(matchedKey, RAW_CHANGE_PASSWORD, encoder);
                assertEquals(CHANGE_ENCRYPTED_PASSWORD, user.getPassword());
            }

            @Test
            @DisplayName("패스워드 인증키를 null로 변경한다.")
            void shouldPasswordCredentialsKeySetNull() {
                user.resetPassword(matchedKey, RAW_CHANGE_PASSWORD, encoder);
                assertNull(user.getPasswordCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("계정 인증키 할당")
    class GeneratedCredentialsKey {

        private User user;
        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);
            this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);

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
            private Collection<AuthorityCode> authorityCodes;

            @BeforeEach
            void setup() {
                when(key.matches(any())).thenReturn(UserKeyMatchedResult.MATCHED);

                this.authorityCodes = new HashSet<>(Arrays.asList(
                        new AuthorityCode("CODE1"),
                        new AuthorityCode("CODE2"),
                        new AuthorityCode("CODE3")));
                user.generateCredentialsKey(keyGenerator);
                user.credentials("KEY", authorityCodes);
            }

            @Test
            @DisplayName("UserAlreadyExistsException이 발생해야 한다.")
            void shouldThrowsUserAlreadyExistsException() {
                assertThrows(UserAlreadyExistsException.class, () -> user.generateCredentialsKey(keyGenerator));
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

        private User user;
        private UserCredentialsKey key;

        @BeforeEach
        void setup() {
            this.key = mock(UserCredentialsKey.class);
            this.user = new User(RAW_EMAIL, RAW_PASSWORD, encoder);
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
}