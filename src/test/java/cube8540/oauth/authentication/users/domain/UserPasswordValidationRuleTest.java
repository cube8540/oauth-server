package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("유저 패스워드 유효성 검사기 테스트")
class UserPasswordValidationRuleTest {

    private UserPasswordValidationRule rule;
    private User user;

    @BeforeEach
    void setup() {
        this.rule = new UserPasswordValidationRule();
        this.user = mock(User.class);
    }

    @Test
    @DisplayName("메시지 검사")
    void message() {
        ValidationError error = rule.error();

        assertEquals(UserPasswordValidationRule.PROPERTY, error.getProperty());
        assertEquals(UserPasswordValidationRule.MESSAGE, error.getMessage());
    }

    @Nested
    @DisplayName("유효성 검사")
    class Validation {

        @Nested
        @DisplayName("패스워드가 유효하지 않을시")
        class WhenEmailInvalid {

            @BeforeEach
            void setup() {
                UserPassword password = mock(UserPassword.class);
                when(user.getPassword()).thenReturn(password);
                when(password.isValid()).thenReturn(Boolean.FALSE);
            }

            @Test
            @DisplayName("패스워드 유효성 검사시 false가 반환되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("패스워드가 null 일시")
        class WhenEmailNull {

            @Test
            @DisplayName("패스워드 유효성 검사시 false가 반환되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(user);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("유효성 검사 대상이 null 일시")
        class WhenTargetNull {

            @Test
            @DisplayName("유효성 검사시 false가 반환되어야 한다.")
            void shouldValidReturnsFalse() {
                boolean isValid = rule.isValid(null);
                assertFalse(isValid);
            }
        }

        @Nested
        @DisplayName("패스워드가 유효할시")
        class WhenEmailValid {

            @BeforeEach
            void setup() {
                UserPassword password = mock(UserPassword.class);
                when(user.getPassword()).thenReturn(password);
                when(password.isValid()).thenReturn(Boolean.TRUE);
            }

            @Test
            @DisplayName("패스워드 유효성 검사시 true가 반환되어야 한다.")
            void shouldValidReturnsTrue() {
                boolean isValid = rule.isValid(user);
                assertTrue(isValid);
            }
        }
    }

}