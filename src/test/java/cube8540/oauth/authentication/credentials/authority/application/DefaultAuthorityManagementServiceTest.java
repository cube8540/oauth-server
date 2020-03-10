package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import cube8540.oauth.authentication.credentials.authority.error.AuthorityNotFoundException;
import cube8540.oauth.authentication.credentials.authority.error.AuthorityRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
            long count = service.countAuthority(AuthorityApplicationTestHelper.RAW_CODE);

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
                assertThrows(AuthorityNotFoundException.class, () -> service.getAuthority(AuthorityApplicationTestHelper.RAW_CODE));
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
                this.request = new AuthorityRegisterRequest(AuthorityApplicationTestHelper.RAW_CODE, AuthorityApplicationTestHelper.DESCRIPTION, true);
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
                Assertions.assertEquals(ErrorCodes.EXISTS_IDENTIFIER, error.getCode());
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
                    this.request = new AuthorityRegisterRequest(AuthorityApplicationTestHelper.RAW_CODE, AuthorityApplicationTestHelper.DESCRIPTION, true);
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
                    this.request = new AuthorityRegisterRequest(AuthorityApplicationTestHelper.RAW_CODE, AuthorityApplicationTestHelper.DESCRIPTION, false);
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
                AuthorityModifyRequest request = new AuthorityModifyRequest(AuthorityApplicationTestHelper.MODIFY_DESCRIPTION, false);

                assertThrows(AuthorityNotFoundException.class, () -> service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request));
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
                    this.request = new AuthorityModifyRequest(AuthorityApplicationTestHelper.MODIFY_DESCRIPTION, true);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 true 로 변경해야 한다.")
                void shouldSearchedAuthorityChangedBasicOptionTrue() {
                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);

                    verify(authority, times(1)).settingBasicAuthority();
                }

                @Test
                @DisplayName("settingNotBasicAuthority API 는 호출하지 않아야 한다.")
                void shouldNotCallSettingNotBasicAuthority() {
                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);

                    verify(authority, never()).settingNotBasicAuthority();
                }

                @Test
                @DisplayName("권한의 정보를 변경후 저장해야 한다.")
                void shouldSaveAuthorityAfterModifyAuthorityInformation() {
                    InOrder inOrder = inOrder(repository, authority);

                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);
                    inOrder.verify(authority, times(1)).setDescription(AuthorityApplicationTestHelper.MODIFY_DESCRIPTION);
                    inOrder.verify(authority, times(1)).settingBasicAuthority();
                    inOrder.verify(repository, times(1)).save(authority);
                }
            }

            @Nested
            @DisplayName("권한 타입을 기본 권한으로 변경하는 요청일시")
            class WhenRequestChangeAuthorityToNotBasicAuthority extends AuthorityFoundSetup {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = new AuthorityModifyRequest(AuthorityApplicationTestHelper.MODIFY_DESCRIPTION, false);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 false 로 변경해야 한다.")
                void shouldSearchedAuthorityChangedBasicOptionFalse() {
                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);

                    verify(authority, times(1)).settingNotBasicAuthority();
                }

                @Test
                @DisplayName("settingBasicAuthority API 는 호출하지 않아야 한다.")
                void shouldNotCallSettingBasicAuthority() {
                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);

                    verify(authority, never()).settingBasicAuthority();
                }

                @Test
                @DisplayName("권한의 정보를 변경후 저장해야 한다.")
                void shouldSaveAuthorityAfterModifyAuthorityInformation() {
                    InOrder inOrder = inOrder(repository, authority);

                    service.modifyAuthority(AuthorityApplicationTestHelper.RAW_CODE, request);
                    inOrder.verify(authority, times(1)).setDescription(AuthorityApplicationTestHelper.MODIFY_DESCRIPTION);
                    inOrder.verify(authority, times(1)).settingNotBasicAuthority();
                    inOrder.verify(repository, times(1)).save(authority);
                }
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
                assertThrows(AuthorityNotFoundException.class, () -> service.removeAuthority(AuthorityApplicationTestHelper.RAW_CODE));
            }
        }

        @Nested
        @DisplayName("삭제할 권한이 저장소에 저장되어 있을시")
        class WhenRemoveTargetAuthorityIsRegisteredInRepository extends AuthorityFoundSetup {

            @Test
            @DisplayName("저장소에서 찾은 권한을 삭제해야 한다.")
            void shouldRemoveSearchedAuthority() {
                service.removeAuthority(AuthorityApplicationTestHelper.RAW_CODE);
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

        @Test
        @DisplayName("요청 받은 코드를 저장소에 저장해야 한다.")
        void shouldSaveRequestingCodeToRepository() {
            ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

            service.registerAuthority(request());
            verify(repository, times(1)).save(authorityCaptor.capture());
            Assertions.assertEquals(AuthorityApplicationTestHelper.CODE, authorityCaptor.getValue().getCode());
        }

        @Test
        @DisplayName("요청 받은 권한의 설명을 저장소에 저장해야 한다.")
        void shouldSaveRequestingAuthorityDescriptionToRepository() {
            ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

            service.registerAuthority(request());
            verify(repository, times(1)).save(authorityCaptor.capture());
            Assertions.assertEquals(AuthorityApplicationTestHelper.DESCRIPTION, authorityCaptor.getValue().getDescription());
        }

        protected abstract AuthorityRegisterRequest request();
    }
}