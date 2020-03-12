package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("자원 아이디 유효성 검사기 테스트")
class SecuredResourceIdRuleTest {

    private static final String RAW_RESOURCE_ID = "RESOURCE-ID";
    private static final SecuredResourceId RESOURCE_ID = new SecuredResourceId(RAW_RESOURCE_ID);

    private SecuredResourceIdRule rule;

    @BeforeEach
    void setup() {
        this.rule = new SecuredResourceIdRule();
    }

    @Test
    @DisplayName("에러 메시지 확인")
    void checkErrorMessage() {
        ValidationError excepted = new ValidationError(SecuredResourceIdRule.DEFAULT_PROPERTY, SecuredResourceIdRule.DEFAULT_MESSAGE);

        assertEquals(excepted, rule.error());
    }

    @Test
    @DisplayName("자원 아이디가 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void ifResourceIdIsNullValidationResultIsFalse() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(null);

        assertFalse(rule.isValid(resource));
    }

    @Test
    @DisplayName("자원 아이디 값이 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void ifResourceIdValuesIsNulLValidationResultIsFalse() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(new SecuredResourceId(null));

        assertFalse(rule.isValid(resource));
    }

    @Test
    @DisplayName("자원 아이디 값이 null 이 아닐시 유효성 검사 결과는 true 가 반환되어야 한다.")
    void ifResourceIdIsNotNullValidationResultIsTrue() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getResourceId()).thenReturn(RESOURCE_ID);

        assertTrue(rule.isValid(resource));
    }

}