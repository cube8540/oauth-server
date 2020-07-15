package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.ADD_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.ADD_REQUEST_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.MODIFY_RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.RAW_MODIFY_RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.RAW_RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.RAW_RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.REMOVE_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.REMOVE_REQUEST_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.REQUEST_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.makeDefaultSecuredResource;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.makeEmptyResourceRepository;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.makeResourceRepository;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.makeValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 자원 관리 서비스 테스트")
class DefaultSecuredResourceManagementServiceTest {

    @Test
    @DisplayName("이미 등록된 리소스 영속화")
    void persistResourceToAlreadyRegisteredInRepository() {
        SecuredResourceRegisterRequest request = new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST", null);
        SecuredResource resource = makeDefaultSecuredResource();
        SecuredResourceRepository repository = makeResourceRepository(RESOURCE_ID, resource);
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        ResourceRegisterException exception = assertThrows(ResourceRegisterException.class, () -> service.registerNewResource(request));
        assertEquals(ErrorCodes.EXISTS_IDENTIFIER, exception.getCode());
    }

    @Test
    @DisplayName("새 리소스 등록")
    void registerNewResource() {
        ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);
        SecuredResourceRegisterRequest request = new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST", REQUEST_AUTHORITIES);
        SecuredResourceRepository repository = makeEmptyResourceRepository();
        SecuredResourceValidationPolicy policy = makeValidationPolicy();
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        service.setValidationPolicy(policy);

        service.registerNewResource(request);
        verifySaveAfterValidation(policy.resourceIdRule(), resourceCaptor, repository);
        verifySaveAfterValidation(policy.resourceRule(), resourceCaptor, repository);
        verifySaveAfterValidation(policy.methodRule(), resourceCaptor, repository);
        verifySaveAfterValidation(policy.scopeAuthoritiesRule(), resourceCaptor, repository);
        verifySaveAfterValidation(policy.roleAuthoritiesRule(), resourceCaptor, repository);
        assertEquals(RESOURCE_ID, resourceCaptor.getValue().getResourceId());
        assertEquals(RESOURCE_URI, resourceCaptor.getValue().getResource());
        assertEquals(ResourceMethod.POST, resourceCaptor.getValue().getMethod());
        assertEquals(AUTHORITIES, resourceCaptor.getValue().getAuthorities());
    }

    @Test
    @DisplayName("저장소에 등록 되지 않은 리소스 수정")
    void modifyNotRegisteredResourceInRepository() {
        SecuredResourceModifyRequest request = new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", null, null);
        SecuredResourceRepository repository = makeEmptyResourceRepository();
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () -> service.modifyResource(RAW_RESOURCE_ID, request));
        assertEquals(ErrorCodes.NOT_FOUND, exception.getCode());
    }

    @Test
    @DisplayName("리소스 수정")
    void modifyResource() {
        SecuredResourceModifyRequest request = new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", ADD_REQUEST_AUTHORITIES, REMOVE_REQUEST_AUTHORITIES);
        SecuredResource resource = makeDefaultSecuredResource();
        SecuredResourceRepository repository = makeResourceRepository(RESOURCE_ID, resource);
        SecuredResourceValidationPolicy policy = makeValidationPolicy();
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        service.setValidationPolicy(policy);

        service.modifyResource(RAW_RESOURCE_ID, request);
        InOrder inOrder = inOrder(resource, repository);
        inOrder.verify(resource, times(1)).changeResourceInfo(MODIFY_RESOURCE_URI, ResourceMethod.PUT);
        REMOVE_AUTHORITIES.forEach(auth -> inOrder.verify(resource, times(1)).removeAuthority(auth.getAuthority(), auth.getAuthorityType()));
        ADD_AUTHORITIES.forEach(auth -> inOrder.verify(resource, times(1)).addAuthority(auth.getAuthority(), auth.getAuthorityType()));
        inOrder.verify(resource, times(1)).validation(policy);
        inOrder.verify(repository, times(1)).save(resource);
    }

    @Test
    @DisplayName("저장소에 등록 되지 않은 리소스 삭제")
    void removeNotRegisteredResourceInRepository() {
        SecuredResourceRepository repository = makeEmptyResourceRepository();
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () -> service.removeResource(RAW_RESOURCE_ID));
        assertEquals(ErrorCodes.NOT_FOUND, exception.getCode());
    }

    @Test
    @DisplayName("리소스 삭제")
    void removeResource() {
        SecuredResource resource = makeDefaultSecuredResource();
        SecuredResourceRepository repository = makeResourceRepository(RESOURCE_ID, resource);
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(repository);

        service.removeResource(RAW_RESOURCE_ID);
        verify(repository, times(1)).delete(resource);
    }

    private void verifySaveAfterValidation(ValidationRule<SecuredResource> rule, ArgumentCaptor<SecuredResource> argumentCaptor, SecuredResourceRepository repository) {
        InOrder inOrder = inOrder(rule, repository);
        inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
        inOrder.verify(repository, times(1)).save(argumentCaptor.capture());

        for (SecuredResource resource : argumentCaptor.getAllValues()) {
            assertEquals(argumentCaptor.getAllValues().get(0), resource);
        }
    }
}