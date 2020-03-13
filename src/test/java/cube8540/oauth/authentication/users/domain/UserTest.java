package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.users.domain.exception.UserAuthorizationException;
import cube8540.oauth.authentication.users.domain.exception.UserErrorCodes;
import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("유저 계정 테스트")
class UserTest {

    @Nested
    @DisplayName("유효성 검사")
    class Validation {

        @Nested
        @DisplayName("허용된 이메일이 아닐시")
        class WhenUserEmailNotAllowed {
            private ValidationError emailError;
            private UserValidationPolicy policy;

            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.emailError = new ValidationError(UserTestHelper.EMAIL_ERROR_PROPERTY, UserTestHelper.EMAIL_ERROR_MESSAGE);

                ValidationRule<User> emailRule = UserTestHelper.mockValidationRule().configReturnFalse(user).validationError(emailError).build();
                ValidationRule<User> passwordRule = UserTestHelper.mockValidationRule().configReturnTrue(user).build();

                this.policy = UserTestHelper.mockValidationPolicy().emailRule(emailRule).passwordRule(passwordRule).build();
            }

            @Test
            @DisplayName("UserInvalidException 이 발생해야 하며 예외 클래스에 이메일 에러 메시지가 포함되어야 한다.")
            void shouldThrowsUserInvalidExceptionAndContainsErrorMessage() {
                UserInvalidException exception = assertThrows(UserInvalidException.class, () -> user.validation(policy));

                assertTrue(exception.getErrors().contains(emailError));
            }
        }

        @Nested
        @DisplayName("허용된 패스워드가 아닐시")
        class WhenUserPasswordNotAllowed {
            private ValidationError passwordError;
            private UserValidationPolicy policy;

            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.passwordError = new ValidationError(UserTestHelper.PASSWORD_ERROR_PROPERTY, UserTestHelper.PASSWORD_ERROR_MESSAGE);

                ValidationRule<User> emailRule = UserTestHelper.mockValidationRule().configReturnTrue(user).build();
                ValidationRule<User> passwordRule = UserTestHelper.mockValidationRule().configReturnFalse(user).validationError(passwordError).build();

                this.policy = UserTestHelper.mockValidationPolicy().emailRule(emailRule).passwordRule(passwordRule).build();
            }

            @Test
            @DisplayName("UserInvalidException 이 발생해야 하며 예외 클래스에 패스워드 에러 메시지가 포함되어야 한다.")
            void shouldThrowsUserInvalidExceptionAndContainsErrorMessage() {
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
            private PasswordEncoder encoder;

            private User user;

            @BeforeEach
            void setup(){
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.encoder  = UserTestHelper.mockPasswordEncoder().mismatches().build();
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class,
                        () -> user.changePassword(UserTestHelper.PASSWORD, UserTestHelper.CHANGE_PASSWORD, encoder));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_PASSWORD 이어야 한다.")
            void shouldErrorCodeIsInvalidPassword() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.changePassword(UserTestHelper.PASSWORD, UserTestHelper.CHANGE_PASSWORD, encoder));
                Assertions.assertEquals(UserErrorCodes.INVALID_PASSWORD, e.getCode());
            }
        }

        @Nested
        @DisplayName("이전에 사용하던 패스워드가 일치할시")
        class WhenExistingPasswordMatched {
            private PasswordEncoder encoder;

            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.encoder = UserTestHelper.mockPasswordEncoder().matches().build();
            }

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 저장하여야 한다.")
            void shouldSaveGivenPassword() {
                user.changePassword(UserTestHelper.PASSWORD, UserTestHelper.CHANGE_PASSWORD, encoder);

                Assertions.assertEquals(UserTestHelper.CHANGE_PASSWORD, user.getPassword());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 분실")
    class ForgotPassword {
        private UserCredentialsKey credentialsKey;
        private UserCredentialsKeyGenerator keyGenerator;

        private User user;

        @BeforeEach
        void setup() {
            this.credentialsKey = UserTestHelper.mockCredentialsKey().build();
            this.keyGenerator = UserTestHelper.mockKeyGenerator(credentialsKey);
            this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
        }

        @Test
        @DisplayName("키 생성기에서 반환된 키를 저장해야 한다.")
        void shouldSaveCreatedKeyByGivenGenerator() {
            user.forgotPassword(keyGenerator);

            assertEquals(credentialsKey, user.getPasswordCredentialsKey());
        }
    }

    @Nested
    @DisplayName("패스워드 초기화")
    class ResetPassword {

        @Nested
        @DisplayName("패스워드 인증키가 할당되지 않았을시")
        class WhenKeyNotGenerated {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_KEY 이어야 한다.")
            void shouldErrorCodeIsInvalidKey() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));

                assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
            }
        }

        @Nested
        @DisplayName("키가 매칭되지 않을시")
        class WhenKeyNotMatched {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);

                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().mismatches(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user.forgotPassword(keyGenerator);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_KEY 이어야 한다.")
            void shouldErrorCodeIsInvalidKey() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));

                assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
            }
        }

        @Nested
        @DisplayName("키가 만료되었을시")
        class WhenKeyExpired {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);

                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().expired(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user.forgotPassword(keyGenerator);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));
            }

            @Test
            @DisplayName("에러 코드는 KEY_EXPIRED 이어야 한다.")
            void shouldErrorCodeIsKeyExpired() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD));

                assertEquals(UserErrorCodes.KEY_EXPIRED, e.getCode());
            }
        }

        @Nested
        @DisplayName("패스워드 인증키가 옳바를시")
        class WhenKeyMatched {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);

                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().matches(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user.forgotPassword(keyGenerator);
            }

            @Test
            @DisplayName("인자로 받은 변경될 패스워드를 저장하여야 한다.")
            void shouldSaveGivenPassword() {
                user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD);

                Assertions.assertEquals(UserTestHelper.CHANGE_PASSWORD, user.getPassword());
            }

            @Test
            @DisplayName("패스워드 인증키를 null 로 변경한다.")
            void shouldPasswordCredentialsKeySetNull() {
                user.resetPassword(UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY, UserTestHelper.CHANGE_PASSWORD);

                assertNull(user.getPasswordCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("계정 인증키 할당")
    class GeneratedCredentialsKey {

        @Nested
        @DisplayName("인증받지 않은 계정일시")
        class WhenNotCredentialsAccount {
            private UserCredentialsKey key;
            private UserCredentialsKeyGenerator keyGenerator;

            private User user;

            @BeforeEach
            void setup() {
                this.key = UserTestHelper.mockCredentialsKey().build();
                this.keyGenerator = UserTestHelper.mockKeyGenerator(key);
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
            }

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
            private UserCredentialsKeyGenerator keyGenerator;

            private User user;

            @BeforeEach
            void setup() {
                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().matches(UserTestHelper.RAW_CREDENTIALS_KEY).build();

                this.keyGenerator = UserTestHelper.mockKeyGenerator(key);
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.user.generateCredentialsKey(keyGenerator);
                this.user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, UserTestHelper.AUTHORITIES_CODE);
            }

            @Test
            @DisplayName("UserAuthorizationException 아 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.generateCredentialsKey(keyGenerator));
            }

            @Test
            @DisplayName("에러 코드는 ALREADY_CREDENTIALS 이어야 한다.")
            void shouldErrorCodeIsAlreadyCredentials() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.generateCredentialsKey(keyGenerator));

                assertEquals(UserErrorCodes.ALREADY_CREDENTIALS, e.getCode());
            }
        }

        @Nested
        @DisplayName("이미 인증 받았지만 할당된 권한이 없을시")
        class WhenAlreadyCertificationNotHaveAuthoritiesAccount {
            private UserCredentialsKey key;
            private UserCredentialsKeyGenerator keyGenerator;

            private User user;

            @BeforeEach
            void setup() {
                this.key = UserTestHelper.mockCredentialsKey().matches(UserTestHelper.RAW_CREDENTIALS_KEY).build();
                this.keyGenerator = UserTestHelper.mockKeyGenerator(key);
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.user.generateCredentialsKey(keyGenerator);
                this.user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptySet());
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

        @Nested
        @DisplayName("인증키가 할당되지 않았을시")
        class WhenKeyNotGenerated {
            private User user;

            @BeforeEach
            void setup() {
                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_KEY 이어야 한다.")
            void shouldErrorCodeIsInvalidKey() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));

                assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
            }
        }

        @Nested
        @DisplayName("인증키가 매칭되지 않을시")
        class WhenKeyNotMatched {
            private User user;

            @BeforeEach
            void setup() {
                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().mismatches(UserTestHelper.RAW_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));
            }

            @Test
            @DisplayName("에러 코드는 INVALID_KEY 이어야 한다.")
            void shouldErrorCodeIsInvalidKey() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));

                assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
            }
        }

        @Nested
        @DisplayName("인증키가 만료되었을시")
        class WhenKeyExpired {
            private User user;

            @BeforeEach
            void setup() {
                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().expired(UserTestHelper.RAW_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("UserAuthorizationException 이 발생해야 한다.")
            void shouldThrowsUserAuthorizationException() {
                assertThrows(UserAuthorizationException.class, () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));
            }

            @Test
            @DisplayName("에러 코드는 KEY_EXPIRED 이어야 한다.")
            void shouldErrorCodeIsKeyExpired() {
                UserAuthorizationException e = assertThrows(UserAuthorizationException.class,
                        () -> user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, Collections.emptyList()));

                assertEquals(UserErrorCodes.KEY_EXPIRED, e.getCode());
            }
        }

        @Nested
        @DisplayName("인증키가 매칭될시")
        class WhenKeyMatched {
            private User user;

            @BeforeEach
            void setup() {
                UserCredentialsKey key = UserTestHelper.mockCredentialsKey().matches(UserTestHelper.RAW_CREDENTIALS_KEY).build();
                UserCredentialsKeyGenerator keyGenerator = UserTestHelper.mockKeyGenerator(key);

                this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
                this.user.generateCredentialsKey(keyGenerator);
            }

            @Test
            @DisplayName("인자로 받은 권한을 저장해야한다.")
            void shouldSaveGivenAuthorities() {
                user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, UserTestHelper.AUTHORITIES_CODE);

                Assertions.assertEquals(UserTestHelper.AUTHORITIES_CODE, user.getAuthorities());
            }

            @Test
            @DisplayName("인증키를 null로 설정해야 한다.")
            void shouldCredentialsKeySetNull() {
                user.credentials(UserTestHelper.RAW_CREDENTIALS_KEY, UserTestHelper.AUTHORITIES_CODE);

                assertNull(user.getCredentialsKey());
            }
        }
    }

    @Nested
    @DisplayName("패스워드 암호화")
    class PasswordEncrypting {
        private PasswordEncoder encoder;

        private User user;

        @BeforeEach
        void setup() {
            this.encoder = UserTestHelper.mockPasswordEncoder().encode().build();
            this.user = new User(UserTestHelper.RAW_EMAIL, UserTestHelper.PASSWORD);
        }

        @Test
        @DisplayName("패스워드를 암호화하여 저장해야 한다.")
        void shouldSaveEncryptedPassword() {
            user.encrypted(encoder);

            Assertions.assertEquals(UserTestHelper.ENCRYPTED_PASSWORD, user.getPassword());
        }
    }
}