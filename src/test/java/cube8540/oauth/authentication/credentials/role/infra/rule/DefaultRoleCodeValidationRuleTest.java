package cube8540.oauth.authentication.credentials.role.infra.rule;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 권한 코드 유효성 검사 테스트")
class DefaultRoleCodeValidationRuleTest {

    private static final AuthorityCode AUTHORITY_CODE_WITH_NULL = new AuthorityCode(null);
    private static final AuthorityCode AUTHORITY_CODE_WITH_EMPTY = new AuthorityCode("");

    private static final AuthorityCode AUTHORITY_CODE = new AuthorityCode("ROLE_USER");

    private DefaultRoleCodeValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultRoleCodeValidationRule();
    }

    @Test
    @DisplayName("권한 코드가 null 일시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void authorityCodeIsNullValidationResultShouldReturnFalse() {
        Role role = mock(Role.class);

        when(role.getCode()).thenReturn(null);

        assertFalse(rule.isValid(role));
    }

    @Test
    @DisplayName("권한 코드의 값이 null 일시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void authorityCodeValueIsNullValidationResultShouldReturnFalse() {
        Role role = mock(Role.class);

        when(role.getCode()).thenReturn(AUTHORITY_CODE_WITH_NULL);

        assertFalse(rule.isValid(role));
    }

    @Test
    @DisplayName("권한 코드의 값이 빈 문자열 일시 유효성 검사 결과는 'false'가 반환 되어야 한다.")
    void authorityCodeValueIsEmptyStringValidationResultShouldReturnFalse() {
        Role role = mock(Role.class);

        when(role.getCode()).thenReturn(AUTHORITY_CODE_WITH_EMPTY);

        assertFalse(rule.isValid(role));
    }

    @Test
    @DisplayName("권한 코드가 유효할시 유효성 검사 결과는 'true'가 반환 되어야 한다.")
    void authorityCodeIsAllowedValidationResultShouldReturnTrue() {
        Role role = mock(Role.class);

        when(role.getCode()).thenReturn(AUTHORITY_CODE);

        assertTrue(rule.isValid(role));
    }

}