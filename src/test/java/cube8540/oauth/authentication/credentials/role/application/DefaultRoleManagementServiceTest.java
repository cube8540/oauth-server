package cube8540.oauth.authentication.credentials.role.application;

import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.oauth.authentication.credentials.role.domain.RoleRepository;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleNotFoundException;
import cube8540.oauth.authentication.credentials.role.domain.exception.RoleRegisterException;
import cube8540.oauth.authentication.credentials.role.infra.RoleValidationPolicy;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.NEW_DESCRIPTION;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.RAW_AUTHORITY_CODE;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.mocKValidationRule;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.mockRole;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.mockRoleRepository;
import static cube8540.oauth.authentication.credentials.role.application.RoleApplicationTestHelper.mockValidationPolicy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 권한 관리 서비스 테스트")
class DefaultRoleManagementServiceTest {

    @Nested
    @DisplayName("새 권한 등록")
    class RegisterNewRole {

        @Nested
        @DisplayName("저장소에 이미 저장 되어 있는 권한 일시")
        class WhenExistingRoleInRepository {
            private RoleRegisterRequest registerRequest;

            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                Role role = mockRole().configDefault().build();
                RoleRepository repository = mockRoleRepository().registerRole(role).build();

                this.registerRequest = new RoleRegisterRequest(RAW_AUTHORITY_CODE, DESCRIPTION, true);
                this.service = new DefaultRoleManagementService(repository);
            }

            @Test
            @DisplayName("RoleRegisterException이 발생 해야 하며, 에러 코드는 EXISTS_IDENTIFIER 이어야 한다.")
            void shouldThrowRoleRegisterExceptionAndErrorCodeIsExistsIdentifier() {
                RoleRegisterException e = assertThrows(RoleRegisterException.class, () -> service.registerNewRole(registerRequest));
                assertEquals(ErrorCodes.EXISTS_IDENTIFIER, e.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 등록되지 않은 권한 일시")
        class WhenNotRegisteredRole {
            private ValidationRule<Role> roleCodeRule;
            private RoleRegisterRequest registerRequest;

            private RoleRepository repository;
            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                this.repository = mockRoleRepository().emptyRole().build();
                this.roleCodeRule  = mocKValidationRule().configValidationTrue().build();

                RoleValidationPolicy policy = mockValidationPolicy().roleCodeRule(roleCodeRule).build();

                this.registerRequest = new RoleRegisterRequest(RAW_AUTHORITY_CODE, DESCRIPTION, true);
                this.service = new DefaultRoleManagementService(repository);
                this.service.setValidationPolicy(policy);
            }

            @Test
            @DisplayName("요청 받은 권한 코드의 유효성을 검사 후 저장 해야 한다.")
            void shouldSaveRoleAfterRoleCodeValidation() {
                ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);

                service.registerNewRole(registerRequest);
                verifySaveAfterValidation(roleCodeRule, roleCaptor);
                assertEquals(AUTHORITY_CODE, roleCaptor.getValue().getCode());
            }

            @Test
            @DisplayName("요청 받은 권한의 설명을 저장해야 한다.")
            void shouldSaveRoleDescription() {
                ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);

                service.registerNewRole(registerRequest);
                verify(repository, times(1)).save(roleCaptor.capture());
                assertEquals(DESCRIPTION, roleCaptor.getValue().getDescription());
            }

            @Test
            @DisplayName("요청 받은 권한의 기본 권한 여부를 저장 해야 한다.")
            void shouldSaveAuthorityBasicOrNot() {
                ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);

                service.registerNewRole(registerRequest);
                verify(repository, times(1)).save(roleCaptor.capture());
                assertTrue(roleCaptor.getValue().isBasic());
            }

            private void verifySaveAfterValidation(ValidationRule<Role> rule, ArgumentCaptor<Role> argumentCaptor) {
                InOrder inOrder = inOrder(rule, repository);
                inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
                inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
                assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
            }
        }
    }

    @Nested
    @DisplayName("권한 수정")
    class ModifyRole {

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있지 않을시")
        class WhenModifyRoleNotRegisteredInRepository {
            private RoleModifyRequest modifyRequest;

            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                this.modifyRequest = new RoleModifyRequest(NEW_DESCRIPTION, false);

                RoleRepository repository = mockRoleRepository().emptyRole().build();
                this.service = new DefaultRoleManagementService(repository);
            }

            @Test
            @DisplayName("RoleNotFoundException이 발생 해야 한다.")
            void shouldThrowRoleNotFoundException() {
                assertThrows(RoleNotFoundException.class, () -> service.modifyRole(RAW_AUTHORITY_CODE, modifyRequest));
            }
        }

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있을시")
        class WhenModifyRoleRegisteredInRepository {
            private RoleModifyRequest modifyRequest;

            private Role role;
            private RoleRepository repository;
            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                this.role = mockRole().configDefault().build();
                this.modifyRequest = new RoleModifyRequest(NEW_DESCRIPTION, false);
                this.repository = mockRoleRepository().registerRole(this.role).build();
                this.service = new DefaultRoleManagementService(repository);
            }

            @Test
            @DisplayName("권한의 설명 변경 후 저장소에 저장 해야 한다.")
            void shouldModifyRoleDescriptionAndSaveRepository() {
                InOrder inOrder = inOrder(role, repository);

                service.modifyRole(RAW_AUTHORITY_CODE, modifyRequest);
                inOrder.verify(role, times(1)).setDescription(NEW_DESCRIPTION);
                inOrder.verify(repository, times(1)).save(role);
            }

            @Test
            @DisplayName("권한의 기본 여부를 변경 후 저장소에 저장 해야 한다.")
            void shouldMoidfyBasicOrNotAndSaveRepository() {
                InOrder inOrder = inOrder(role, repository);

                service.modifyRole(RAW_AUTHORITY_CODE, modifyRequest);
                inOrder.verify(role, times(1)).setBasic(false);
                inOrder.verify(repository, times(1)).save(role);
            }
        }
    }

    @Nested
    @DisplayName("권한 삭제")
    class RemoveRole {

        @Nested
        @DisplayName("삭제할 권한이 저장소에 저장 되어 있지 않을시")
        class WhenRemoveRoleNotRegisteredInRepository {
            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                RoleRepository repository = mockRoleRepository().emptyRole().build();

                this.service = new DefaultRoleManagementService(repository);
            }

            @Test
            @DisplayName("RoleNotFoundException이 발생 해야 한다.")
            void shouldThrowRoleNotFoundException() {
                assertThrows(RoleNotFoundException.class, () -> service.removeRole(RAW_AUTHORITY_CODE));
            }
        }

        @Nested
        @DisplayName("삭제할 권한이 저장소에 저장 되어 있을시")
        class WhenRemoveRoleRegisteredInRepository {

            private Role role;
            private RoleRepository repository;
            private DefaultRoleManagementService service;

            @BeforeEach
            void setup() {
                this.role = mockRole().configDefault().build();
                this.repository = mockRoleRepository().registerRole(role).build();
                this.service = new DefaultRoleManagementService(this.repository);
            }

            @Test
            @DisplayName("저장되어 있는 권한을 삭제해야 한다.")
            void shouldRemoveRegisteredRole() {
                service.removeRole(RAW_AUTHORITY_CODE);

                verify(repository, times(1)).delete(role);
            }
        }
    }
}