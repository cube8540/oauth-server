package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.infra.DefaultUserPasswordValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 패스워드 유효성 검사 테스트")
class DefaultUserPasswordValidationRuleTest {

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

    @Test
    @DisplayName("허용되는 길이보다 작은 패스워드 일시")
    void passwordLessThenAllowedLengthValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_LESS_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("허용되는 길이보다 큰 패스워드 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void passwordGraterThenAllowedLengthValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_GRATER_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("대문자가 포함되지 않은 패스워드 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void passwordWithoutUppercaseValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_UPPERCASE);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("소문자가 포함되지 않은 패스워드 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void passwordWithoutLowercaseValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_LOWERCASE);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("특수 문자가 포함되지 않은 패스워드 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void passwordWithoutSpecialCharacterValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_WITHOUT_SPECIAL_CHARACTER);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("허용되지 않은 특수문자가 포함된 패스워드 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void passwordWithNotAllowedSpecialCharacterValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getPassword()).thenReturn(PASSWORD_WITH_NOT_ALLOWED_SPECIAL_CHARACTER);

        assertFalse(rule.isValid(user));
    }
}