package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.Username;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 아이디 검사 테스트")
class DefaultUsernameValidationRuleTest {

    private static final Username USERNAME_GRATER_THEN_ALLOWED_LENGTH = new Username("username1234username1234username1234username1234");
    private static final Username USERNAME_LESS_THEN_ALLOWED_LENGTH = new Username("u12");
    private static final Username USERNAME_WITHOUT_NUMBER = new Username("username");
    private static final Username USERNAME_WITHOUT_CHARACTER = new Username("1234");
    private static final Username USERNAME_WITH_SPECIAL_CHARACTER = new Username("username!@#1234");
    private static final Username USERNAME = new Username("username1234");

    private DefaultUsernameValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultUsernameValidationRule();
    }

    @Test
    @DisplayName("아이디가 허용 되는 문자 길이 보다 클시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void usernameGraterThenAllowedLengthValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME_GRATER_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("아이디가 허용 되는 문자 길이 보다 작을시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void usernameLessThenAllowedLengthValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME_LESS_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("아이디에 숫자가 포함 되지 않았을시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void usernameNotContainsNumberValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME_WITHOUT_NUMBER);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("아이디에 문자가 포함 되지 않았을시 유효성 검사 결과는 'false'가 반환되여야 한다.")
    void usernameNotContainsCharacterValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME_WITHOUT_CHARACTER);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("아이디에 특수문자가 포함 되어 있을시 유효성 검사 결과는 'false'가 반횐 되어야 한다.")
    void usernameContainsSpacialCharacterValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME_WITH_SPECIAL_CHARACTER);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("아이디가 유효할시 유효성 검사 결과는 'true'가 반환 되어야 한다.")
    void usernameIsAllowedValidationResultShouldReturnTrue() {
        User user = mock(User.class);

        when(user.getUsername()).thenReturn(USERNAME);

        assertTrue(rule.isValid(user));
    }

}