package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.ADDED_ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.CODE;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.DESCRIPTION;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.MODIFY_DESCRIPTION;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_ADDED_ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_CODE;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.RAW_REMOVE_ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.REMOVE_ACCESSIBLE_RESOURCES;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockAuthorityValidationPolicy;
import static cube8540.oauth.authentication.credentials.authority.application.AuthorityApplicationTestHelper.mockAuthorityValidationRule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 권한 관리 서비스 테스트")
class DefaultAuthorityManagementServiceTest {

    @Nested
    @DisplayName("권한 카운팅")
    class CountingAuthority {
        private long randomCount;

        private DefaultAuthorityManagementService service;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);

            AuthorityRepository repository = AuthorityApplicationTestHelper.mockAuthorityRepository().count(randomCount).build();
            this.service = new DefaultAuthorityManagementService(repository);
        }

        @Test
        @DisplayName("저장소에서 검색된 권한의 카운터를 반환해야 한다.")
        void shouldReturnsAuthorityCode() {
            long count = service.countAuthority(RAW_CODE);

            assertEquals(randomCount, count);
        }
    }

    @Nested
    @DisplayName("권한 검색")
    class GetAuthority {

        @Nested
        @DisplayName("저장소에 권한이 없을시")
        class AuthorityNotFound extends AuthorityNotFoundSetup {

            @Test
            @DisplayName("AuthorityNotFoundException 이 발생해야 한다.")
            void shouldThrowsAuthorityNotFoundException() {
                assertThrows(AuthorityNotFoundException.class, () -> service.getAuthority(RAW_CODE));
            }
        }
    }

    @Nested
    @DisplayName("새 권한 등록")
    class RegisterNewAuthority {

        @Nested
        @DisplayName("등록을 요청한 권한이 이미 저장소에 저장되어 있을시")
        class WhenRequestingRegisterAuthorityAlreadyExistsInRepository extends AuthorityFoundSetup {
            private AuthorityRegisterRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, true, RAW_ACCESSIBLE_RESOURCES);
            }

            @Test
            @DisplayName("AuthorityRegistrationException 이 발생해야 한다.")
            void shouldThrowAuthorityRegistrationException() {
                assertThrows(AuthorityRegisterException.class, () -> service.registerAuthority(request));
            }

            @Test
            @DisplayName("에러 코드는 ALREADY_EXISTS_ID 이어야 한다.")
            void shouldErrorCodeIsAlreadyExistsId() {
                AuthorityRegisterException error = assertThrows(AuthorityRegisterException.class, () -> service.registerAuthority(request));
                assertEquals(ErrorCodes.EXISTS_IDENTIFIER, error.getCode());
            }
        }

        @Nested
        @DisplayName("등록을 요청한 권한이 저장소에 없을시")
        class WhenRequestingRegisterAuthorityNotExistsInRepository {

            @Nested
            @DisplayName("등록할 권한이 기본 권한일시")
            class WhenRegisterAuthorityIsBasicAuthority extends AuthorityRegisterSetup {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, true, RAW_ACCESSIBLE_RESOURCES);
                }

                @Test
                @DisplayName("기본 권한 여부는 true 로 저장해야 한다.")
                void shouldAuthorityBasicSetTrue() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request);
                    verify(repository, times(1)).save(authorityCaptor.capture());
                    assertTrue(authorityCaptor.getValue().isBasic());
                }

                @Override
                public AuthorityRegisterRequest request() {
                    return request;
                }
            }

            @Nested
            @DisplayName("등록할 권한이 기본 권한이 아닐시")
            class WhenRegisterAuthorityIsNotBasicAuthority extends AuthorityRegisterSetup {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, false, RAW_ACCESSIBLE_RESOURCES);
                }

                @Test
                @DisplayName("기본 권한 여부는 false 로 저장해야 한다.")
                void shouldAuthorityBasicSetFalse() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request);
                    verify(repository, times(1)).save(authorityCaptor.capture());
                    assertFalse(authorityCaptor.getValue().isBasic());
                }

                @Override
                public AuthorityRegisterRequest request() {
                    return request;
                }
            }

            @Nested
            @DisplayName("등록할 접근 자원이 null 일시")
            class WhenAccessibleResourceIsNull extends AuthorityRegisterSetup {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, false, null);
                }

                @Test
                @DisplayName("자원에 접근 권한은 추가하지 않아야 한다.")
                void shouldNotSaveAccessibleResourceToAuthority() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request);
                    verify(repository, times(1)).save(authorityCaptor.capture());
                    assertNull(authorityCaptor.getValue().getAccessibleResources());
                }

                @Override
                protected AuthorityRegisterRequest request() {
                    return request;
                }
            }

            @Nested
            @DisplayName("등록할 접근 자원이 null 이 아닐시")
            class WhenAccessibleResourceIsNotNull extends AuthorityRegisterSetup {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, false, RAW_ACCESSIBLE_RESOURCES);
                }

                @Test
                @DisplayName("요청 받은 접근 자원을 유효성 검사 후 저장소에 저장해야 한다.")
                void shouldSaveRequestingAccessibleResourcesToRepositoryAfterValidation() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request());
                    verifySaveAfterValidation(accessibleResourcesRule, authorityCaptor);
                    assertEquals(ACCESSIBLE_RESOURCES, authorityCaptor.getValue().getAccessibleResources());
                }

                @Override
                protected AuthorityRegisterRequest request() {
                    return request;
                }
            }
        }
    }

    @Nested
    @DisplayName("권한 수정")
    class ModifyAuthority {

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있지 않을시")
        class WhenModifyTargetAuthorityNotRegisteredInRepository extends AuthorityNotFoundSetup {

            @Test
            @DisplayName("AuthorityNotFoundException 이 발생해야 한다.")
            void shouldThrowsAuthorityNotFoundException() {
                AuthorityModifyRequest request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, false,
                        RAW_ADDED_ACCESSIBLE_RESOURCES, RAW_REMOVE_ACCESSIBLE_RESOURCES);

                assertThrows(AuthorityNotFoundException.class, () -> service.modifyAuthority(RAW_CODE, request));
            }
        }

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있을시")
        class WhenModifyTargetAuthorityRegisteredInRepository {

            @Nested
            @DisplayName("권한 타입을 기본 권한으로 변경하는 요청일시")
            class WhenRequestChangeAuthorityToBasicAuthority extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, true, null, null);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 true 로 변경해야 한다.")
                void shouldSearchedAuthorityChangedBasicOptionTrue() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, times(1)).settingBasicAuthority();
                }

                @Test
                @DisplayName("settingNotBasicAuthority API 는 호출하지 않아야 한다.")
                void shouldNotCallSettingNotBasicAuthority() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, never()).settingNotBasicAuthority();
                }

                @Test
                @DisplayName("권한의 정보를 변경후 저장해야 한다.")
                void shouldSaveAuthorityAfterModifyAuthorityInformation() {
                    InOrder inOrder = inOrder(repository, authority);

                    service.modifyAuthority(RAW_CODE, request);
                    inOrder.verify(authority, times(1)).setDescription(MODIFY_DESCRIPTION);
                    inOrder.verify(authority, times(1)).settingBasicAuthority();
                    inOrder.verify(repository, times(1)).save(authority);
                }
            }

            @Nested
            @DisplayName("권한 타입을 기본 권한으로 변경하는 요청이 아닐시")
            class WhenRequestChangeAuthorityToNotBasicAuthority extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, false, null, null);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 false 로 변경해야 한다.")
                void shouldSearchedAuthorityChangedBasicOptionFalse() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, times(1)).settingNotBasicAuthority();
                }

                @Test
                @DisplayName("settingBasicAuthority API 는 호출하지 않아야 한다.")
                void shouldNotCallSettingBasicAuthority() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, never()).settingBasicAuthority();
                }

                @Test
                @DisplayName("권한의 정보를 변경후 저장해야 한다.")
                void shouldSaveAuthorityAfterModifyAuthorityInformation() {
                    InOrder inOrder = inOrder(repository, authority);

                    service.modifyAuthority(RAW_CODE, request);
                    inOrder.verify(authority, times(1)).setDescription(MODIFY_DESCRIPTION);
                    inOrder.verify(authority, times(1)).settingNotBasicAuthority();
                    inOrder.verify(repository, times(1)).save(authority);
                }
            }

            @Nested
            @DisplayName("추가할 접근 자원이 null 일시")
            class WhenAddAccessibleResourceIsNull extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(DESCRIPTION, false, null, RAW_REMOVE_ACCESSIBLE_RESOURCES);
                }

                @Test
                @DisplayName("권한의 접근 자원을 추가하지 않아야 한다.")
                void shouldNotAddAccessibleResourceToAuthority() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, never()).addAccessibleResource(any());
                }
            }

            @Nested
            @DisplayName("추가할 접근 자원이 null 이 아닐시")
            class WhenAddedAccessibleResourceIsNotNull extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;
                private AuthorityValidationPolicy policy;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(DESCRIPTION, false, RAW_ADDED_ACCESSIBLE_RESOURCES, RAW_REMOVE_ACCESSIBLE_RESOURCES);
                    this.policy = mockAuthorityValidationPolicy().build();
                    this.service.setValidationPolicy(policy);
                }

                @Test
                @DisplayName("권한에 요청한 접근 자원을 추가 후 유효성 검사를 하고 저장소에 저장해야 한다.")
                void shouldSaveRepositoryAfterRequestingAddAccessibleResourceToAuthorityAndValidation() {
                    InOrder inOrder = inOrder(authority, repository);

                    service.modifyAuthority(RAW_CODE, request);
                    ADDED_ACCESSIBLE_RESOURCES.forEach(resource -> inOrder.verify(authority, times(1)).addAccessibleResource(resource));
                    inOrder.verify(authority, times(1)).validation(policy);
                    inOrder.verify(repository, times(1)).save(authority);
                }
            }

            @Nested
            @DisplayName("삭제할 접근 자원이 null 일시")
            class WhenRemoveAccessibleResourceIsNull extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(DESCRIPTION, false, RAW_ADDED_ACCESSIBLE_RESOURCES, null);
                }

                @Test
                @DisplayName("권한의 접근 자원을 삭제하지 않아야 한다.")
                void shouldNotRemoveAccessibleResourceToAuthority() {
                    service.modifyAuthority(RAW_CODE, request);

                    verify(authority, never()).removeAccessibleResource(any());
                }
            }
        }

        @Nested
        @DisplayName("삭제할 접근 자원이 null 이 아닐시")
        class WhenRemoveAccessibleResourceIsNotNull extends AuthorityFoundSetup {
            private AuthorityModifyRequest request;
            private AuthorityValidationPolicy policy;

            @BeforeEach
            void setupRequest() {
                this.request = new AuthorityModifyRequest(DESCRIPTION, false, RAW_ADDED_ACCESSIBLE_RESOURCES, RAW_REMOVE_ACCESSIBLE_RESOURCES);
                this.policy = mockAuthorityValidationPolicy().build();
                this.service.setValidationPolicy(policy);
            }

            @Test
            @DisplayName("권한에 요청한 접근 자원을 삭제 후 유효성 검사를 하고 저장소에 저장해야 한다.")
            void shouldSaveRepositoryAfterRequestingRemoveAccessibleResourceToAuthorityAndValidation() {
                InOrder inOrder = inOrder(authority, repository);

                service.modifyAuthority(RAW_CODE, request);
                REMOVE_ACCESSIBLE_RESOURCES.forEach(resource -> inOrder.verify(authority, times(1)).removeAccessibleResource(resource));
                inOrder.verify(authority, times(1)).validation(policy);
                inOrder.verify(repository, times(1)).save(authority);
            }
        }
    }

    @Nested
    @DisplayName("권한 삭제")
    class RemoveAuthority {

        @Nested
        @DisplayName("삭제할 권한을 저장소에 저장되어 있지 않을시")
        class WhenRemoveTargetAuthorityIsNotRegisteredInRepository extends AuthorityNotFoundSetup {

            @Test
            @DisplayName("AuthorityNotFoundException 이 발생해야 한다.")
            void shouldAuthorityNotFoundException() {
                assertThrows(AuthorityNotFoundException.class, () -> service.removeAuthority(RAW_CODE));
            }
        }

        @Nested
        @DisplayName("삭제할 권한이 저장소에 저장되어 있을시")
        class WhenRemoveTargetAuthorityIsRegisteredInRepository extends AuthorityFoundSetup {

            @Test
            @DisplayName("저장소에서 찾은 권한을 삭제해야 한다.")
            void shouldRemoveSearchedAuthority() {
                service.removeAuthority(RAW_CODE);
                verify(repository, times(1)).delete(authority);
            }
        }
    }

    private static abstract class AuthorityNotFoundSetup {
        protected AuthorityRepository repository;
        protected DefaultAuthorityManagementService service;

        @BeforeEach
        void setup() {
            this.repository = AuthorityApplicationTestHelper.mockAuthorityRepository().emptyAuthority().count(0).build();
            this.service = new DefaultAuthorityManagementService(repository);
        }
    }

    private static abstract class AuthorityFoundSetup {
        protected AuthorityRepository repository;
        protected DefaultAuthorityManagementService service;
        protected Authority authority;

        @BeforeEach
        void setup() {
            this.authority = AuthorityApplicationTestHelper.configDefaultAuthority().build();
            this.repository = AuthorityApplicationTestHelper.mockAuthorityRepository().registerAuthority(authority).count(1).build();
            this.service = new DefaultAuthorityManagementService(repository);
        }
    }

    private static abstract class AuthorityRegisterSetup extends AuthorityNotFoundSetup {
        protected ValidationRule<Authority> codeRule;
        protected ValidationRule<Authority> accessibleResourcesRule;

        @BeforeEach
        void setupValidation() {
            this.codeRule = mockAuthorityValidationRule().configReturnTrue().build();
            this.accessibleResourcesRule = mockAuthorityValidationRule().configReturnTrue().build();

            this.service.setValidationPolicy(mockAuthorityValidationPolicy().codeRule(codeRule).accessibleResourceRule(accessibleResourcesRule).build());
        }

        @Test
        @DisplayName("요청 받은 코드를 유효성 검사 후 저장소에 저장해야 한다.")
        void shouldSaveRequestingCodeToRepositoryAfterValidation() {
            ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

            service.registerAuthority(request());
            verifySaveAfterValidation(codeRule, authorityCaptor);
            assertEquals(CODE, authorityCaptor.getValue().getCode());
        }

        @Test
        @DisplayName("요청 받은 권한의 설명을 저장소에 저장해야 한다.")
        void shouldSaveRequestingAuthorityDescriptionToRepository() {
            ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

            service.registerAuthority(request());
            verify(repository, times(1)).save(authorityCaptor.capture());
            assertEquals(DESCRIPTION, authorityCaptor.getValue().getDescription());
        }

        protected void verifySaveAfterValidation(ValidationRule<Authority> rule, ArgumentCaptor<Authority> argumentCaptor) {
            InOrder inOrder = inOrder(rule, repository);
            inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
            inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
            assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
        }

        protected abstract AuthorityRegisterRequest request();
    }
}