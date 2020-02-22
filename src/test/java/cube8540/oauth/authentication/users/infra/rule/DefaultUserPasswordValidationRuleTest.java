package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 패스워드 유효성 검사 룰 테스트")
class DefaultUserPasswordValidationRuleTest {

    private static final String PASSWORD = "Password1234!@#$";
    private static final String PASSWORD_LESS_THEN_ALLOWED_LENGTH = "Pas123!@";
    private static final String PASSWORD_GRATER_THEN_ALLOWED_LENGTH = "Password1234!@#$Password1234!@#$Password1234!@#$";
    private static final String PASSWORD_WITHOUT_UPPERCASE = "password1234!@#$";
    private static final String PASSWORD_WITHOUT_LOWERCASE = "PASSWORD1234!@#$";
    private static final String PASSWORD_WITHOUT_SPECIAL_CHARACTER = "Password12341234";
    private static final String PASSWORD_WITH_NOT_ALLOWED_SPECIAL_CHARACTER = "Password1234!@#$.";

    private DefaultUserPasswordValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultUserPasswordValidationRule();
    }

    @Nested
    @DisplayName("허용되지 않은 패스워드 유효성 검사")
    class ValidateNotAllowedPassword {

        private User user;

        @BeforeEach
        void setup() {
            this.user = mock(User.class);
        }

        @Nested
        @DisplayName("허용되는 길이보다 작은 패스워드를 생성할시")
        class WhenLessThenAllowedLength {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_LESS_THEN_ALLOWED_LENGTH);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("허용되는 길이보다 큰 패스워드를 생성할시")
        class WhenGraterThenAllowedLength {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_GRATER_THEN_ALLOWED_LENGTH);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("대문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutUppercasePassword {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_UPPERCASE);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("소문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutLowercasePassword {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_LOWERCASE);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("특수문자가 포함되지 않은 패스워드를 생성할시")
        class WhenWithoutSpecialCharacterPassword {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_SPECIAL_CHARACTER);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("허용되지 않은 특수문자가 포함되는 패스워드를 생성할시")
        class WhenWithNotAllowedSpecialCharacterPassword {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(PASSWORD_WITH_NOT_ALLOWED_SPECIAL_CHARACTER);
            }

            @Test
            @DisplayName("유효성 검사시 false가 반환 되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("패스워드가 null 일시")
        class WhenNull {

            @BeforeEach
            void setup() {
                when(user.getPassword()).thenReturn(null);
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
    @DisplayName("허용되는 패스워드 유효성 검사")
    class InitializeAllowedPassword {

        private User user;

        @BeforeEach
        void setup() {
            this.user = mock(User.class);
            when(user.getPassword()).thenReturn(PASSWORD);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환 되어야 한다.")
        void shouldValidReturnsTrue() {
            boolean isValid = rule.isValid(user);
            assertTrue(isValid);
        }
    }

}