package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 유저 이메일 검사 테스트")
class DefaultUserEmailValidationRuleTest {

    private static final UserEmail EMAIL_WITHOUT_AT = new UserEmail("emailemail.com");
    private static final UserEmail EMAIL_WITHOUT_DOT = new UserEmail("email@emailcom");
    private static final UserEmail EMAIL_START_WITH_DOMAIN = new UserEmail("email.com@email");
    private static final UserEmail EMAIL_WITH_NULL = new UserEmail(null);

    private DefaultUserEmailValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultUserEmailValidationRule();
    }

    @Test
    @DisplayName("이메일에 골뱅이표(@)가 없을시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void emailNotContainsAtValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn(EMAIL_WITHOUT_AT);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("이메일에 닷(.)이 없을시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void emailNotContainsDotValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn(EMAIL_WITHOUT_DOT);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("이메일이 도메인으로 시작할시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void emailStartWithDomainValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn(EMAIL_START_WITH_DOMAIN);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("이메일 값이 null 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void emailValueIsNullValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn(EMAIL_WITH_NULL);

        assertFalse(rule.isValid(user));
    }

    @Test
    @DisplayName("이메일이 null 일시 유효성 검사 결과는 'false'가 반환되어야 한다.")
    void emailIsNullValidationResultShouldReturnFalse() {
        User user = mock(User.class);

        when(user.getEmail()).thenReturn(null);

        assertFalse(rule.isValid(user));
    }
}