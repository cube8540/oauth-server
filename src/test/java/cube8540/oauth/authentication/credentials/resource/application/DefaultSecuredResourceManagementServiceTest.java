package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceNotFoundException;
import cube8540.oauth.authentication.credentials.resource.domain.exception.ResourceRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
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
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.mockResourceRepository;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.mockResourceValidationPolicy;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.mockResourceValidationRule;
import static cube8540.oauth.authentication.credentials.resource.application.SecuredResourceApplicationTestHelper.mockSecuredResource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 자원 관리 서비스 테스트")
class DefaultSecuredResourceManagementServiceTest {

    @Nested
    @DisplayName("새 리소스 추가")
    class RegisterNewResource {

        @Nested
        @DisplayName("등록을 요청한 권한이 이미 저장소에 저장되어 있을시")
        class WhenRequestingRegisterResourceAlreadyExistsInRepository extends SecuredResourceFoundSetup {
            private SecuredResourceRegisterRequest registerRequest;

            @BeforeEach
            void setupRequest() {
                this.registerRequest = new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST", null);
            }

            @Test
            @DisplayName("ResourceRegisterException 이 발생해야 하며 에러 코드는 ALREADY_EXISTS_ID 이어야 한다.")
            void shouldThrowsResourceRegisterExceptionAndErrorCodeIsAlreadyExistsId() {
                ResourceRegisterException exception = assertThrows(ResourceRegisterException.class, () -> service.registerNewResource(registerRequest));
                assertEquals(ErrorCodes.EXISTS_IDENTIFIER, exception.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 저장되지 않은 권한일시")
        class WhenNotRegisterInRepository extends SecuredResourceNotFoundSetup {

            @Nested
            @DisplayName("요청한 접근 권한이 null 일시")
            class WhenRequestingAuthoritiesIsNull extends SecuredResourceRegisterSetup {

                @Override
                protected SecuredResourceRegisterRequest request() {
                    return new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST", null);
                }

                @Test
                @DisplayName("보호 자원에 접근 권한을 추가 하지 않아야 한다.")
                void shouldNotAddAuthoritiesToSecuredResource() {
                    ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);

                    service.registerNewResource(registerRequest);
                    verify(repository, times(1)).save(resourceCaptor.capture());
                    assertNull(resourceCaptor.getValue().getAuthorities());
                }
            }

            @Nested
            @DisplayName("요청한 접근 권한이 null 이 아닐시")
            class WhenRequestingAuthoritiesIsNotNull extends SecuredResourceRegisterSetup {

                @Override
                protected SecuredResourceRegisterRequest request() {
                    return new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST", REQUEST_AUTHORITIES);
                }

                @Test
                @DisplayName("요청 받은 접근 권한을 유효성 검사 후 저장소에 저장해야 한다.")
                void shouldSaveRequestingAuthoritiesToRepositoryAfterValidation() {
                    ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);

                    service.registerNewResource(registerRequest);
                    verifySaveAfterValidation(scopeRule, resourceCaptor);
                    assertEquals(AUTHORITIES, resourceCaptor.getValue().getAuthorities());
                }
            }
        }
    }

    @Nested
    @DisplayName("리소스 수정")
    class ModifyResource {

        @Nested
        @DisplayName("수정할 리소스가 저장소에 등록되어 있지 않을시")
        class WhenModifyResourceIsNotRegisteredInRepository extends SecuredResourceNotFoundSetup {
            private SecuredResourceModifyRequest modifyRequest;

            @BeforeEach
            void setupRequest() {
                this.modifyRequest = new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", null, null);
            }

            @Test
            @DisplayName("ResourceNotFoundException 이 발생해야 하며 에러 코드는 NOT_FOUND 이어야 한다.")
            void shouldThrowsResourceNotFoundExceptionAndErrorCodeIsNotFound() {
                ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class,
                        () -> service.modifyResource(RAW_RESOURCE_ID, modifyRequest));
                assertEquals(ErrorCodes.NOT_FOUND, exception.getCode());
            }
        }

        @Nested
        @DisplayName("수정할 리소스가 저장소에 등록되어 있을시")
        class WhenModifyResourceIsRegisteredInRepository extends SecuredResourceFoundSetup {

            @Nested
            @DisplayName("삭제할 접근 권한이 null 일시")
            class WhenRemoveAuthoritiesIsNull extends SecuredResourceModifySetup {

                @Override
                protected SecuredResourceModifyRequest request() {
                    return new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", null, null);
                }

                @Test
                @DisplayName("보호 자원의 접근 권한을 삭제하지 않아야 한다.")
                void shouldNotRemoveAuthorityToResource() {
                    service.modifyResource(RAW_RESOURCE_ID, modifyRequest);

                    verify(securedResource, never()).removeAuthority(any(), any());
                }
            }

            @Nested
            @DisplayName("추가할 권한이 null 일시")
            class WhenAddAuthoritiesIsNull extends SecuredResourceModifySetup {

                @Override
                protected SecuredResourceModifyRequest request() {
                    return new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", null, null);
                }

                @Test
                @DisplayName("보호 자원의 접근 권한을 추가하지 않아야 한다.")
                void shouldNotAddAuthorityToResource() {
                    service.modifyResource(RAW_RESOURCE_ID, modifyRequest);

                    verify(securedResource, never()).addAuthority(any(), any());
                }
            }

            @Nested
            @DisplayName("삭제할 접근 권한이 null 이 아닐시")
            class WhenRemoveAuthoritiesIsNotNull extends SecuredResourceModifySetup {

                @Override
                protected SecuredResourceModifyRequest request() {
                    return new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", null, REMOVE_REQUEST_AUTHORITIES);
                }

                @Test
                @DisplayName("보호 자원에 요청한 접근 권한을 삭제 후 유효성 검사를 하고 저장소에 저장해야 한다.")
                void shouldSaveRepositoryAfterRequestingRemoveAuthoritiesToResourceAndValidation() {
                    InOrder inOrder = inOrder(securedResource, repository);

                    service.modifyResource(RAW_RESOURCE_ID, modifyRequest);
                    REMOVE_AUTHORITIES.forEach(auth -> inOrder.verify(securedResource, times(1)).removeAuthority(auth.getAuthority(), auth.getAuthorityType()));
                    inOrder.verify(securedResource, times(1)).validation(policy);
                    inOrder.verify(repository, times(1)).save(securedResource);
                }
            }

            @Nested
            @DisplayName("추가할 접근 권한이 null 이 아닐시")
            class WhenAddAuthoritiesIsNotNull extends SecuredResourceModifySetup {

                @Override
                protected SecuredResourceModifyRequest request() {
                    return new SecuredResourceModifyRequest(RAW_MODIFY_RESOURCE_URI, "PUT", ADD_REQUEST_AUTHORITIES, REMOVE_REQUEST_AUTHORITIES);
                }

                @Test
                @DisplayName("보호 자원에 요청한 접근 권한을 추가 후 유효성 검사를 하고 저장소에 저장해야 한다.")
                void shouldSaveRepositoryAfterRequestingAddAuthoritiesToResourceAndValidation() {
                    InOrder inOrder = inOrder(securedResource, repository);

                    service.modifyResource(RAW_RESOURCE_ID, modifyRequest);
                    ADD_AUTHORITIES.forEach(auth -> inOrder.verify(securedResource, times(1)).addAuthority(auth.getAuthority(), auth.getAuthorityType()));
                    inOrder.verify(securedResource, times(1)).validation(policy);
                    inOrder.verify(repository, times(1)).save(securedResource);
                }
            }
        }
    }

    @Nested
    @DisplayName("리소스 삭제")
    class RemoveResource {

        @Nested
        @DisplayName("삭제할 리소스가 저장소에 등록되어 있지 않을시")
        class WhenRemoveResourceIsNotRegisteredInRepository extends SecuredResourceNotFoundSetup {

            @Test
            @DisplayName("ResourceNotFoundException 이 발생해야 하며 에러 코드는 NOT_FOUND 이어야 한다.")
            void shouldThrowsResourceNotFoundExceptionAndErrorCodeIsNotFound() {
                ResourceNotFoundException exception = assertThrows(ResourceNotFoundException.class, () -> service.removeResource(RAW_RESOURCE_ID));
                assertEquals(ErrorCodes.NOT_FOUND, exception.getCode());
            }
        }

        @Nested
        @DisplayName("삭제할 리소스가 저장소에 등록되어 있을시")
        class WhenRemoveResourceIsRegisteredInRepository extends SecuredResourceFoundSetup {

            @Test
            @DisplayName("검색된 리소스를 저장소에서 삭제해야 한다.")
            void shouldRemoveSearchedResource() {
                service.removeResource(RAW_RESOURCE_ID);

                verify(repository, times(1)).delete(securedResource);
            }
        }
    }

    private static abstract class SecuredResourceNotFoundSetup {
        protected SecuredResourceRepository repository;
        protected DefaultSecuredResourceManagementService service;

        @BeforeEach
        void setup() {
            this.repository = mockResourceRepository().emptyResource().build();
            this.service = new DefaultSecuredResourceManagementService(repository);
        }
    }

    private static abstract class SecuredResourceFoundSetup {
        protected SecuredResourceRepository repository;
        protected DefaultSecuredResourceManagementService service;
        protected SecuredResource securedResource;

        @BeforeEach
        void setup() {
            this.securedResource = mockSecuredResource().resourceId().resource().method().build();
            this.repository = mockResourceRepository().registerResource(securedResource).build();
            this.service = new DefaultSecuredResourceManagementService(repository);
        }
    }

    private static abstract class SecuredResourceRegisterSetup extends SecuredResourceNotFoundSetup {

        protected SecuredResourceRegisterRequest registerRequest;
        protected ValidationRule<SecuredResource> resourceIdRule;
        protected ValidationRule<SecuredResource> resourceRule;
        protected ValidationRule<SecuredResource> methodRule;
        protected ValidationRule<SecuredResource> scopeRule;
        protected ValidationRule<SecuredResource> roleRule;

        @BeforeEach
        void setupRequest() {
            this.registerRequest =  request();
            this.resourceIdRule = mockResourceValidationRule().configReturnTrue().build();
            this.resourceRule = mockResourceValidationRule().configReturnTrue().build();
            this.methodRule = mockResourceValidationRule().configReturnTrue().build();
            this.scopeRule = mockResourceValidationRule().configReturnTrue().build();
            this.roleRule = mockResourceValidationRule().configReturnTrue().build();

            SecuredResourceValidationPolicy policy = mockResourceValidationPolicy().resourceIdRule(resourceIdRule)
                    .resourceRule(resourceRule).methodRule(methodRule).scopeRule(scopeRule).roleRule(roleRule).build();
            this.service.setValidationPolicy(policy);
        }

        @Test
        @DisplayName("요청 받은 자원의 아이디의 유효성을 검사한 후 저장소에 저장해야 한다.")
        void shouldSaveRequestingResourceIdAfterValidation() {
            ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);

            service.registerNewResource(registerRequest);
            verifySaveAfterValidation(resourceIdRule, resourceCaptor);
            assertEquals(RESOURCE_ID, resourceCaptor.getValue().getResourceId());
        }

        @Test
        @DisplayName("요청 받은 자원 정보의 유효성을 검사한 후 저장소에 저장해야 한다.")
        void shouldSaveRequestingResourceInfoAfterValidation() {
            ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);

            service.registerNewResource(registerRequest);
            verifySaveAfterValidation(resourceRule, resourceCaptor);
            assertEquals(RESOURCE_URI, resourceCaptor.getValue().getResource());
        }

        @Test
        @DisplayName("요청 받은 자원 메소드의 유효성을 검사한 후 저장소에 저장해야 한다.")
        void shouldSaveRequestingResourceMethodAfterValidation() {
            ArgumentCaptor<SecuredResource> resourceCaptor = ArgumentCaptor.forClass(SecuredResource.class);

            service.registerNewResource(registerRequest);
            verifySaveAfterValidation(methodRule, resourceCaptor);
            assertEquals(ResourceMethod.POST, resourceCaptor.getValue().getMethod());
        }

        protected void verifySaveAfterValidation(ValidationRule<SecuredResource> rule, ArgumentCaptor<SecuredResource> argumentCaptor) {
            InOrder inOrder = inOrder(rule, repository);
            inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
            inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
            assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
        }

        protected abstract SecuredResourceRegisterRequest request();
    }

    private static abstract class SecuredResourceModifySetup extends SecuredResourceFoundSetup {
        protected SecuredResourceValidationPolicy policy;
        protected SecuredResourceModifyRequest modifyRequest;

        @BeforeEach
        void setupRequest() {
            this.policy = mockResourceValidationPolicy().build();
            this.modifyRequest = request();

            this.service.setValidationPolicy(policy);
        }

        @Test
        @DisplayName("리소스의 정보를 변경한 후 유효성을 검사하여 저장소에 등록해야 한다.")
        void shouldChangeResourceInfoAndSavedRepositoryAfterValidation() {
            InOrder inOrder = inOrder(securedResource, repository);

            service.modifyResource(RAW_RESOURCE_ID, modifyRequest);
            inOrder.verify(securedResource, times(1)).changeResourceInfo(MODIFY_RESOURCE_URI, ResourceMethod.PUT);
            inOrder.verify(securedResource, times(1)).validation(policy);
            inOrder.verify(repository, times(1)).save(securedResource);
        }

        protected abstract SecuredResourceModifyRequest request();
    }
}