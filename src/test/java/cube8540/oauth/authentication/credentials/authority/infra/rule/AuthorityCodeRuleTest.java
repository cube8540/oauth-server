package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorityCodeRuleTest {

    private static final String RAW_CODE = "CODE";
    private static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_CODE);

    private AuthorityCodeRule rule;

    @BeforeEach
    void setup() {
        this.rule = new AuthorityCodeRule();
    }

    @Test
    @DisplayName("에러 메시지 확인")
    void checkErrorMessage() {
        ValidationError excepted = new ValidationError(AuthorityCodeRule.DEFAULT_PROPERTY, AuthorityCodeRule.DEFAULT_MESSAGE);

        assertEquals(excepted, rule.error());
    }

    @Test
    @DisplayName("권한 코드가 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void ifAuthorityCodeIsNullValidationResultIsFalse() {
        Authority authority = mock(Authority.class);

        when(authority.getCode()).thenReturn(null);

        assertFalse(rule.isValid(authority));
    }

    @Test
    @DisplayName("권한 코드가 값이 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void ifAuthorityCodeValuesIsNulLValidationResultIsFalse() {
        Authority authority = mock(Authority.class);

        when(authority.getCode()).thenReturn(new AuthorityCode(null));

        assertFalse(rule.isValid(authority));
    }

    @Test
    @DisplayName("권한 코드 값이 null 이 아닐시 유효성 검사 결과는 true 가 반환되어야 한다.")
    void ifAuthorityCodeIsNotNullValidationResultIsTrue() {
        Authority authority = mock(Authority.class);

        when(authority.getCode()).thenReturn(AUTHORITY_CODE);

        assertTrue(rule.isValid(authority));
    }

}