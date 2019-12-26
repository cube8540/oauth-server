package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("암호화된 패스워드 테스트")
class UserEncryptedPasswordTest {

    private static final String PASSWORD = "$2a$10$MrsAcjEPfD4ktbWEb13SBu.lE2OfGWZ2NPqgUoSTeWA7bvh9.k3WC";
    private static final String ENCRYPTED_PASSWORD = "$2y$10$zMSWRQlgsLcgzD4OuId7l.T2OlqDtpayXbyqWuXIJ7R3BmKC26Bju";

    private UserPasswordEncoder encoder;

    @BeforeEach
    void setup() {
        this.encoder = mock(UserPasswordEncoder.class);
    }

    @Nested
    @DisplayName("암호화된 패스워드 생성")
    class InitializeEncryptedPassword {
        private UserEncryptedPassword password;

        @BeforeEach
        void setup() {
            this.password = new UserEncryptedPassword(PASSWORD);
        }

        @Test
        @DisplayName("생성자로 받은 패스워드를 저장해야 한다.")
        void shouldSaveGivenConstructorVariable() {
            assertEquals(PASSWORD, password.getPassword());
        }

        @Test
        @DisplayName("패스워드 암호화 여부는 true가 반환되어야 한다.")
        void shouldEncryptedReturnsTrue() {
            boolean isEncrypted = password.isEncrypted();
            assertTrue(isEncrypted);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldValidReturnsTrue() {
            boolean isValid = password.isValid();
            assertTrue(isValid);
        }
    }

    @Nested
    @DisplayName("패스워드 암호화")
    class EncryptingPassword {
        private UserEncryptedPassword password;

        @BeforeEach
        void setup() {
            this.password = new UserEncryptedPassword(PASSWORD);
            when(encoder.encoding(PASSWORD)).thenReturn(ENCRYPTED_PASSWORD);
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