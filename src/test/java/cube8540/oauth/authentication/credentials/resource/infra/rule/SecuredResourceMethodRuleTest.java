package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("자원 메소드 유효성 검사기 테스트")
class SecuredResourceMethodRuleTest {

    private SecuredResourceMethodRule rule;

    @BeforeEach
    void setup() {
        this.rule = new SecuredResourceMethodRule();
    }

    @Test
    @DisplayName("에러 메시지 확인")
    void checkErrorMessage() {
        ValidationError excepted = new ValidationError(SecuredResourceMethodRule.DEFAULT_PROPERTY, SecuredResourceMethodRule.DEFAULT_MESSAGE);

        assertEquals(excepted, rule.error());
    }

    @Test
    @DisplayName("메소드가 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void ifMethodIsNullValidationResultIsFalse() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getMethod()).thenReturn(null);

        assertFalse(rule.isValid(resource));
    }

    @Test
    @DisplayName("메소드가 null 이 아닐시 유효성 검사 결과는 true 가 반환되어야 한다.")
    void ifMethodIsNotNullValidationResultIsTrue() {
        SecuredResource resource = mock(SecuredResource.class);

        when(resource.getMethod()).thenReturn(ResourceMethod.POST);

        assertTrue(rule.isValid(resource));
    }

}