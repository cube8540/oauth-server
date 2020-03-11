package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.error.ResourceRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RESOURCE_ID;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RESOURCE_URI;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockResourceRepository;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockResourceValidationPolicy;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockResourceValidationRule;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockSecuredResource;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;

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
                this.registerRequest = new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST");
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
        class WhenNotRegisterInRepository {
            private SecuredResourceRepository repository;
            private SecuredResourceRegisterRequest registerRequest;
            private ValidationRule<SecuredResource> resourceIdRule;
            private ValidationRule<SecuredResource> resourceRule;
            private ValidationRule<SecuredResource> methodRule;

            private DefaultSecuredResourceManagementService service;

            @BeforeEach
            void setup() {
                this.registerRequest = new SecuredResourceRegisterRequest(RAW_RESOURCE_ID, RAW_RESOURCE_URI, "POST");
                this.repository = mockResourceRepository().emptyResource().build();
                this.resourceIdRule = mockResourceValidationRule().configReturnTrue().build();
                this.resourceRule = mockResourceValidationRule().configReturnTrue().build();
                this.methodRule = mockResourceValidationRule().configReturnTrue().build();

                SecuredResourceValidationPolicy policy = mockResourceValidationPolicy().resourceIdRule(resourceIdRule).resourceRule(resourceRule).methodRule(methodRule).build();

                this.service = new DefaultSecuredResourceManagementService(repository);
                this.service.setPolicy(policy);
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

            private void verifySaveAfterValidation(ValidationRule<SecuredResource> rule, ArgumentCaptor<SecuredResource> argumentCaptor) {
                InOrder inOrder = inOrder(rule, repository);
                inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
                inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
                assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
            }
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
}