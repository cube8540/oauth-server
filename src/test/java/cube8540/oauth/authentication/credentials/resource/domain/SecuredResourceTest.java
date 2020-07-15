package cube8540.oauth.authentication.credentials.resource.domain;

import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceInvalidException;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ACCESSIBLE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.AUTHORITY_TYPE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE_METHOD;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ERROR_MESSAGE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.ERROR_PROPERTY;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.RESOURCE_METHOD;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.makeErrorValidation;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.makePassValidation;
import static cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceTestHelper.makeResourceValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("보호 자원 테스트")
class SecuredResourceTest {

    @Test
    @DisplayName("자원 정보 변경")
    void changeResourceInfo() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);

        resource.changeResourceInfo(CHANGE_RESOURCE, CHANGE_RESOURCE_METHOD);
        assertEquals(CHANGE_RESOURCE, resource.getResource());
        assertEquals(CHANGE_RESOURCE_METHOD, resource.getMethod());
    }

    @Test
    @DisplayName("접근 권한 추가")
    void addAuthority() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);

        resource.addAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);
        assertTrue(resource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
    }

    @Test
    @DisplayName("접근 권한 삭제")
    void removeAuthority() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        resource.addAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);

        resource.removeAuthority(RAW_AUTHORITY_CODE, AUTHORITY_TYPE);
        assertFalse(resource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
    }

    @Test
    @DisplayName("허용 되지 않는 리소스 아이디 일때 유효성 검사")
    void validationWhenNotAllowedResourceId() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        ValidationError error = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);
        SecuredResourceValidationPolicy policy = makeResourceValidationPolicy().resourceIdRule(makeErrorValidation(resource, error))
                .resourceRule(makePassValidation(resource))
                .methodRule(makePassValidation(resource))
                .scopeAuthoritiesRule(makePassValidation(resource))
                .roleAuthoritiesRule(makePassValidation(resource)).build();

        ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(policy));
        assertTrue(exception.getErrors().contains(error));
    }

    @Test
    @DisplayName("허용 되지 않은 리소스 일때 유효성 검사")
    void validationWhenNotAllowedResource() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        ValidationError error = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);
        SecuredResourceValidationPolicy policy = makeResourceValidationPolicy().resourceIdRule(makePassValidation(resource))
                .resourceRule(makeErrorValidation(resource, error))
                .methodRule(makePassValidation(resource))
                .scopeAuthoritiesRule(makePassValidation(resource))
                .roleAuthoritiesRule(makePassValidation(resource)).build();

        ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(policy));
        assertTrue(exception.getErrors().contains(error));
    }

    @Test
    @DisplayName("허용 되지 않은 메소드 일떄 유효성 검사")
    void validationWhenNotAllowedMethod() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        ValidationError error = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);
        SecuredResourceValidationPolicy policy = makeResourceValidationPolicy().resourceIdRule(makePassValidation(resource))
                .resourceRule(makePassValidation(resource))
                .methodRule(makeErrorValidation(resource, error))
                .scopeAuthoritiesRule(makePassValidation(resource))
                .roleAuthoritiesRule(makePassValidation(resource)).build();

        ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(policy));
        assertTrue(exception.getErrors().contains(error));
    }

    @Test
    @DisplayName("허용 되지 않은 접근 스코프 일때 유효성 검사")
    void validationWhenNotAllowedScopes() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        ValidationError error = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);
        SecuredResourceValidationPolicy policy = makeResourceValidationPolicy().resourceIdRule(makePassValidation(resource))
                .resourceRule(makePassValidation(resource))
                .methodRule(makePassValidation(resource))
                .scopeAuthoritiesRule(makeErrorValidation(resource, error))
                .roleAuthoritiesRule(makePassValidation(resource)).build();

        ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(policy));
        assertTrue(exception.getErrors().contains(error));
    }

    @Test
    @DisplayName("허용 되지 않은 접근 권한 일때 유효성 검사")
    void validationWhenNotAllowedAuthorities() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        ValidationError error = new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE);
        SecuredResourceValidationPolicy policy = makeResourceValidationPolicy().resourceIdRule(makePassValidation(resource))
                .resourceRule(makePassValidation(resource))
                .methodRule(makePassValidation(resource))
                .scopeAuthoritiesRule(makePassValidation(resource))
                .roleAuthoritiesRule(makeErrorValidation(resource, error)).build();

        ResourceInvalidException exception = assertThrows(ResourceInvalidException.class, () -> resource.validation(policy));
        assertTrue(exception.getErrors().contains(error));
    }
}