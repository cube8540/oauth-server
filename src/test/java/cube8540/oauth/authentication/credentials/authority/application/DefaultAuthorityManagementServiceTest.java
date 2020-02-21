package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityAlreadyException;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityNotFoundException;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 권한 관리 서비스 테스트")
class DefaultAuthorityManagementServiceTest {

    private static final String RAW_CODE = "AUTHORITY-CODE";
    private static final AuthorityCode CODE = new AuthorityCode(RAW_CODE);

    private static final String DESCRIPTION = "DESCRIPTION";
    private static final String MODIFY_DESCRIPTION = "MODIFY-DESCRIPTION";

    private AuthorityRepository repository;
    private DefaultAuthorityManagementService service;

    @BeforeEach
    void setup() {
        this.repository = mock(AuthorityRepository.class);
        this.service = new DefaultAuthorityManagementService(repository);
    }

    @Nested
    @DisplayName("권한 카운팅")
    class CountingAuthority {

        private long randomCount;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);
            when(repository.countByCode(CODE)).thenReturn(randomCount);
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
        class AuthorityNotFound {

            @BeforeEach
            void setup() {
                when(repository.findById(CODE)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("AuthorityNotFoundException이 발생해야 한다.")
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
        class WhenRequestingRegisterAuthorityAlreadyExistsInRepository {

            private AuthorityRegisterRequest request;

            @BeforeEach
            void setup() {
                this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, true);

                when(repository.countByCode(CODE)).thenReturn(1L);
            }

            @Test
            @DisplayName("AuthorityAlreadyException이 발생해야 한다.")
            void shouldThrowsAuthorityAlreadyException() {
                assertThrows(AuthorityAlreadyException.class, () -> service.registerAuthority(request));
            }
        }

        @Nested
        @DisplayName("등록을 요청한 권한이 저장소에 없을시")
        class WhenRequestingRegisterAuthorityNotExistsInRepository {

            private AuthorityRegisterRequest request;

            @BeforeEach
            void setup() {
                this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, false);

                doAnswer(returnsFirstArg()).when(repository).save(isA(Authority.class));
                when(repository.countByCode(CODE)).thenReturn(0L);
            }

            @Test
            @DisplayName("요청 받은 코드를 저장소에 저장해야 한다.")
            void shouldSaveRequestingCodeToRepository() {
                ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                service.registerAuthority(request);
                verify(repository, times(1)).save(authorityCaptor.capture());
                assertEquals(CODE, authorityCaptor.getValue().getCode());
            }

            @Test
            @DisplayName("요청 받은 권한의 설명을 저장소에 저장해야 한다.")
            void shouldSaveRequestingAuthorityDescriptionToRepository() {
                ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                service.registerAuthority(request);
                verify(repository, times(1)).save(authorityCaptor.capture());
                assertEquals(DESCRIPTION, authorityCaptor.getValue().getDescription());
            }

            @Nested
            @DisplayName("등록할 권한이 기본 권한일시")
            class WhenRegisterAuthorityIsBasicAuthority {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, true);
                }

                @Test
                @DisplayName("기본 권한 여부는 true로 저장해야 한다.")
                void shouldAuthorityBasicSetTrue() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request);
                    verify(repository, times(1)).save(authorityCaptor.capture());
                    assertTrue(authorityCaptor.getValue().isBasic());
                }
            }

            @Nested
            @DisplayName("등록할 권한이 기본 권한이 아닐시")
            class WhenRegisterAuthorityIsNotBasicAuthority {
                private AuthorityRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new AuthorityRegisterRequest(RAW_CODE, DESCRIPTION, false);
                }

                @Test
                @DisplayName("기본 권한 여부는 false로 저장해야 한다.")
                void shouldAuthorityBasicSetFalse() {
                    ArgumentCaptor<Authority> authorityCaptor = ArgumentCaptor.forClass(Authority.class);

                    service.registerAuthority(request);
                    verify(repository, times(1)).save(authorityCaptor.capture());
                    assertFalse(authorityCaptor.getValue().isBasic());
                }
            }
        }
    }

    @Nested
    @DisplayName("권한 수정")
    class ModifyAuthority {

        private Authority authority;
        private AuthorityModifyRequest request;

        @BeforeEach
        void setup() {
            this.authority = mock(Authority.class);
            this.request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, false);

            when(authority.getCode()).thenReturn(CODE);
            when(authority.getDescription()).thenReturn(DESCRIPTION);
        }

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있지 않을시")
        class WhenModifyTargetAuthorityNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findById(CODE)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("AuthorityNotFoundException이 발생해야 한다.")
            void shouldThrowsAuthorityNotFoundException() {
                assertThrows(AuthorityNotFoundException.class, () -> service.modifyAuthority(RAW_CODE, request));
            }
        }

        @Nested
        @DisplayName("수정할 권한이 저장소에 저장 되어 있을시")
        class WhenModifyTargetAuthorityRegisteredInRepository {

            @BeforeEach
            void setup() {
                Authority modifiedAuthority = mock(Authority.class);

                when(repository.findById(CODE)).thenReturn(Optional.of(authority));
                when(modifiedAuthority.getCode()).thenReturn(CODE);
                when(modifiedAuthority.getDescription()).thenReturn(MODIFY_DESCRIPTION);
                when(repository.save(authority)).thenReturn(modifiedAuthority);
            }

            @Test
            @DisplayName("권한의 정보를 변경후 저장해야 한다.")
            void shouldSaveAuthorityAfterModifyAuthorityInformation() {
                InOrder inOrder = inOrder(repository, authority);

                service.modifyAuthority(RAW_CODE, request);
                inOrder.verify(authority, times(1)).setDescription(MODIFY_DESCRIPTION);
                inOrder.verify(repository, times(1)).save(authority);
            }

            @Nested
            @DisplayName("권한 타입을 기본 권한으로 변경하는 요청일시")
            class WhenRequestChangeAuthorityToBasicAuthority {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, true);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 true로 변경해야 한다.")
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
            @DisplayName("권한 타입을 기본 권한으로 변경하는 요청일시")
            class WhenRequestChangeAuthorityToNotBasicAuthority {
                private AuthorityModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new AuthorityModifyRequest(MODIFY_DESCRIPTION, false);
                }

                @Test
                @DisplayName("검색된 권한의 기본 권한 여부를 false로 변경해야 한다.")
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
        }
    }

    @Nested
    @DisplayName("권한 삭제")
    class RemoveAuthority {

        @Nested
        @DisplayName("삭제할 권한을 저장소에 저장되어 있지 않을시")
        class WhenRemoveTargetAuthorityIsNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findById(CODE)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("AuthorityNotFoundException이 발생해야 한다.")
            void shouldAuthorityNotFoundException() {
                assertThrows(AuthorityNotFoundException.class, () -> service.removeAuthority(RAW_CODE));
            }
        }

        @Nested
        @DisplayName("삭제할 권한이 저장소에 저장되어 있을시")
        class WhenRemoveTargetAuthorityIsRegisteredInRepository {

            private Authority authority;

            @BeforeEach
            void setup() {
                this.authority = mock(Authority.class);

                when(authority.getCode()).thenReturn(CODE);
                when(authority.getDescription()).thenReturn(DESCRIPTION);
                when(repository.findById(CODE)).thenReturn(Optional.of(authority));
            }

            @Test
            @DisplayName("저장소에서 찾은 권한을 삭제해야 한다.")
            void shouldRemoveSearchedAuthority() {
                service.removeAuthority(RAW_CODE);
                verify(repository, times(1)).delete(authority);
            }
        }
    }
}