package cube8540.oauth.authentication.users.domain;

import cube8540.oauth.authentication.users.domain.exception.UserInvalidException;
import cube8540.oauth.authentication.users.domain.validator.UserEmailValidationRule;
import cube8540.oauth.authentication.users.domain.validator.UserPasswordValidationRule;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("유저 계정 테스트")
class UserTest {

    private static final String RAW_EMAIL = "email@email.com";
    private static final String NOT_ALLOWED_RAW_EMAIL = "email";
    private static final UserEmail EMAIL = new UserEmail(RAW_EMAIL);

    private static final String RAW_PASSWORD = "Password1234!@#$";
    private static final String NOT_ALLOWED_RAW_PASSWORD = "password";
    private static final String RAW_ENCRYPTED_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";
    private static final UserPassword ENCRYPTED_PASSWORD = new UserEncryptedPassword(RAW_ENCRYPTED_PASSWORD);

    private UserPasswordEncoder encoder;

    @BeforeEach
    void setup() {
        this.encoder = mock(UserPasswordEncoder.class);
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
                when(encoder.encoding(RAW_PASSWORD)).thenReturn(RAW_ENCRYPTED_PASSWORD);

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

}