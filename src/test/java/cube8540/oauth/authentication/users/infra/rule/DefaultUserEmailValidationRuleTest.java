package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 이메일 검사룰 테스트")
class DefaultUserEmailValidationRuleTest {

    private static final String EMAIL = "email@email.com";
    private static final String EMAIL_WITHOUT_AT = "emailemail.com";
    private static final String EMAIL_WITHOUT_DOT = "email@emailcom";
    private static final String EMAIL_START_WITH_DOMAIN = "email.com@email";

    private DefaultUserEmailValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultUserEmailValidationRule();
    }

    @Nested
    @DisplayName("허용되지 않는 이메일의 유효성 검사")
    class ValidateNotAllowedEmail {

        private User user;

        @BeforeEach
        void setup() {
            this.user = mock(User.class);
        }

        @Nested
        @DisplayName("골뱅이표(@)가 없을때")
        class WhenWithoutAt {

            @BeforeEach
            void setup() {
                UserEmail email = new UserEmail(EMAIL_WITHOUT_AT);
                when(user.getEmail()).thenReturn(email);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("닷(.)이 없을떄")
        class WhenWithoutDot {

            @BeforeEach
            void setup() {
                UserEmail email = new UserEmail(EMAIL_WITHOUT_DOT);
                when(user.getEmail()).thenReturn(email);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("이메일이 도메인으로 시작할시")
        class WhenStartWithDomain {

            @BeforeEach
            void setup() {
                UserEmail email = new UserEmail(EMAIL_START_WITH_DOMAIN);
                when(user.getEmail()).thenReturn(email);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("null 일시")
        class WhenNull {

            @BeforeEach
            void setup() {
                UserEmail email = new UserEmail(null);
                when(user.getEmail()).thenReturn(email);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }
    }

    @Nested
    @DisplayName("허용되는 이메일의 유효성 검사")
    class ValidateAllowedEmail {

        private User user;

        @BeforeEach
        void setup() {
            this.user = mock(User.class);

            UserEmail email = new UserEmail(EMAIL);
            when(user.getEmail()).thenReturn(email);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldValidReturnsTrue() {
            boolean isValid = rule.isValid(user);
            assertTrue(isValid);
        }
    }

}