package cube8540.oauth.authentication.resource.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.ACCESSIBLE_AUTHORITY;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.CHANGE_RESOURCE_METHOD;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.RESOURCE;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.RESOURCE_METHOD;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.resource.domain.SecuredResourceTestHelper.makePassValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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

        resource.addAuthority(RAW_AUTHORITY_CODE);
        assertTrue(resource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
    }

    @Test
    @DisplayName("접근 권한 삭제")
    void removeAuthority() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);
        resource.addAuthority(RAW_AUTHORITY_CODE);

        resource.removeAuthority(RAW_AUTHORITY_CODE);
        assertFalse(resource.getAuthorities().contains(ACCESSIBLE_AUTHORITY));
    }

    @Test
    @DisplayName("유효 하지 않은 정보가 저장 되어 있을시")
    void resourceDataInvalid() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);

        SecuredResourceValidatorFactory factory = makeErrorValidatorFactory(resource);

        assertThrows(ResourceInvalidException.class, () -> resource.validation(factory));
    }

    @Test
    @DisplayName("모든 데이터가 유효할시")
    void resourceDataAllowed() {
        SecuredResource resource = new SecuredResource(RESOURCE_ID, RESOURCE, RESOURCE_METHOD);

        SecuredResourceValidatorFactory factory = makePassValidatorFactory(resource);

        assertDoesNotThrow(() -> resource.validation(factory));
    }
}