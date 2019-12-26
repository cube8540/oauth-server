package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("이메일 테스트")
class UserEmailTest {

    private static final String EMAIL = "email@email.com";
    private static final String EMAIL_WITHOUT_AT = "emailemail.com";
    private static final String EMAIL_WITHOUT_DOT = "email@emailcom";
    private static final String EMAIL_START_WITH_DOMAIN = "email.com@email";

    @Nested
    @DisplayName("이메일 생성")
    class InitializeEmail {

        private UserEmail email;

        @BeforeEach
        void setup() {
            this.email = new UserEmail(EMAIL);
        }

        @Test
        @DisplayName("생성자로 받은 이메일 저장해야 한다.")
        void shouldSaveGivenConstructorVariableToValue() {
            assertEquals(EMAIL, email.getValue());
        }
    }

    @Nested
    @DisplayName("허용되지 않는 이메일의 유효성 검사")
    class InitializeNotAllowedEmail {

        @Nested
        @DisplayName("골뱅이표(@)가 없을때")
        class WhenWithoutAt {
            private UserEmail email;

            @BeforeEach
            void setup() {
                this.email = new UserEmail(EMAIL_WITHOUT_AT);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = email.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("닷(.)이 없을떄")
        class WhenWithoutDot {
            private UserEmail email;

            @BeforeEach
            void setup() {
                this.email = new UserEmail(EMAIL_WITHOUT_DOT);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = email.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("이메일이 도메인으로 시작할시")
        class WhenStartWithDomain {
            private UserEmail email;

            @BeforeEach
            void setup() {
                this.email = new UserEmail(EMAIL_START_WITH_DOMAIN);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = email.isValid();
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("null 일시")
        class WhenNull {
            private UserEmail email;

            @BeforeEach
            void setup() {
                this.email = new UserEmail(null);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = email.isValid();
                assertFalse(isValid);
            }
        }
    }

    @Nested
    @DisplayName("허용되는 이메일의 유효성 검사")
    class InitializeAllowedEmail {
        private UserEmail email = new UserEmail(EMAIL);

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldValidReturnsTrue() {
            boolean isValid = email.isValid();
            assertTrue(isValid);
        }
    }

}