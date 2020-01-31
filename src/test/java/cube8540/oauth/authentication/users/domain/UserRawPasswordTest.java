package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("패스워드 테스트")
class UserRawPasswordTest {

    private static final String PASSWORD = "Password1234!@#$";
    private static final String PASSWORD_LESS_THEN_ALLOWED_LENGTH = "Pas123!@";
    private static final String PASSWORD_GRATER_THEN_ALLOWED_LENGTH = "Password1234!@#$Password1234!@#$Password1234!@#$";
    private static final String PASSWORD_WITHOUT_UPPERCASE = "password1234!@#$";
    private static final String PASSWORD_WITHOUT_LOWERCASE = "PASSWORD1234!@#$";
    private static final String PASSWORD_WITHOUT_SPECIAL_CHARACTER = "Password12341234";
    private static final String PASSWORD_WITH_NOT_ALLOWED_SPECIAL_CHARACTER = "Password1234!@#$.";
    private static final String ENCRYPTED_PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";

    private UserPasswordEncoder encoder;

    @BeforeEach
    void setup() {
        this.encoder = mock(UserPasswordEncoder.class);
    }

    @Nested
    @DisplayName("패스워드 생성")
    class InitializePassword {
        private UserRawPassword password;

        @BeforeEach
        void setup() {
            this.password = new UserRawPassword(PASSWORD);
        }

        @Test
        @DisplayName("생성자로 받은 문자열을 저장해야 한다.")
        void shouldSaveGivenConstructorVariableValue() {
            assertEquals(PASSWORD, password.getPassword());
        }

        @Test
        @DisplayName("패스워드의 암호화 여부는 false가 반환되어야 한다.")
        void shouldEncryptedReturnsFalse() {
            boolean isEncrypted = password.isEncrypted();
            assertFalse(isEncrypted);
        }
    }

    @Nested
    @DisplayName("허용되지 않은 패스워드 유효성 검사")
    class InitializeNotAllowedPassword {

        @Nested
        @DisplayName("허용되는 길이보다 작은 패스워드를 생성할시")
        class WhenLessThenAllowedLength {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_LESS_THEN_ALLOWED_LENGTH);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("허용되는 길이보다 큰 패스워드를 생성할시")
        class WhenGraterThenAllowedLength {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_GRATER_THEN_ALLOWED_LENGTH);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("대문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutUppercasePassword {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_WITHOUT_UPPERCASE);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("소문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutLowercasePassword {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_WITHOUT_LOWERCASE);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("특수문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutSpecialCharacterPassword {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_WITHOUT_SPECIAL_CHARACTER);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("허용되지 않은 특수문자가 포함되는 패스워드를 생성할시")
        class WhenWithNotAllowedSpecialCharacterPassword {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(PASSWORD_WITH_NOT_ALLOWED_SPECIAL_CHARACTER);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("패스워드가 null 일시")
        class WhenNull {
            private UserRawPassword password;

            @BeforeEach
            void setup() {
                this.password = new UserRawPassword(null);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = password.isValid();
                assertFalse(isValid);
            }
        }
    }

    @Nested
    @DisplayName("허용되는 패스워드 유효성 검사")
    class InitializeAllowedPassword {
        private UserRawPassword password;

        @BeforeEach
        void setup() {
            this.password = new UserRawPassword(PASSWORD);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환 되어야 한다.")
        void shouldValidReturnsTrue() {
            boolean isValid = password.isValid();
            assertTrue(isValid);
        }
    }

    @Nested
    @DisplayName("패스워드 암호화")
    class EncryptingPassword {
        private UserRawPassword password;

        @BeforeEach
        void setup() {
            when(encoder.encode(PASSWORD)).thenReturn(ENCRYPTED_PASSWORD);

            this.password = new UserRawPassword(PASSWORD);
        }

        @Test
        @DisplayName("인코더에서 암호화 되어 나온 패스워드가 반환되어야 한다.")
        void shouldReturnsEncoderEncryptedPassword() {
            UserPassword encryptedPassword = password.encrypted(encoder);

            assertEquals(UserEncryptedPassword.class, encryptedPassword.getClass());
            assertEquals(ENCRYPTED_PASSWORD, encryptedPassword.getPassword());
        }
    }
}