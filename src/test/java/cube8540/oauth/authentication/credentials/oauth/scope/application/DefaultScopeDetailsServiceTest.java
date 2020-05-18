package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeRegisterException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 스코프 디테일 서비스 테스트")
class DefaultScopeDetailsServiceTest {

    @Nested
    @DisplayName("새 스코프 등록")
    class RegisterNewScope {

        @Nested
        @DisplayName("저장소에 이미 저장되어 있는 스코프 일시")
        class WhenExistingScopeInRepository {
            private OAuth2ScopeRegisterRequest registerRequest;

            private DefaultScopeDetailsService service;

            @BeforeEach
            void setup() {
                OAuth2Scope scope = ScopeApplicationTestHelper.mockScope().configDefault().build();
                OAuth2ScopeRepository repository = ScopeApplicationTestHelper.mockScopeRepository().registerScope(scope).build();

                this.registerRequest = new OAuth2ScopeRegisterRequest(ScopeApplicationTestHelper.RAW_SCOPE_ID, ScopeApplicationTestHelper.DESCRIPTION, ScopeApplicationTestHelper.RAW_AUTHORITIES);
                this.service = new DefaultScopeDetailsService(repository);
            }

            @Test
            @DisplayName("ScopeRegisterException 이 발생해야 하며 에러 코드는 EXISTS_IDENTIFIER 이어야 한다.")
            void shouldThrowScopeRegisterExceptionAndErrorCodeIsExistsIdentifier() {
                ScopeRegisterException e = assertThrows(ScopeRegisterException.class, () -> service.registerNewScope(registerRequest));
                Assertions.assertEquals(ErrorCodes.EXISTS_IDENTIFIER, e.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 없는 스코프일시")
        class WhenNotExistingScopeId {

            @Nested
            @DisplayName("요청 받은 접근 권한이 null 일시")
            class WhenRequestingAccessibleAuthorityIsNull extends ScopeRegisterAssertSetup {

                @Override
                protected OAuth2ScopeRegisterRequest registerRequest() {
                    return new OAuth2ScopeRegisterRequest(ScopeApplicationTestHelper.RAW_SCOPE_ID, ScopeApplicationTestHelper.DESCRIPTION, null);
                }

                @Test
                @DisplayName("스코프에 저장소를 저장하지 않아야 한다.")
                void shouldNotSaveAccessibleAuthority() {
                    ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

                    service.registerNewScope(registerRequest);
                    verify(repository, times(1)).save(scopeCaptor.capture());
                    assertNull(scopeCaptor.getValue().getAccessibleAuthority());
                }
            }

            @Nested
            @DisplayName("요청 받은 접근 권한이 null 이 아닐시")
            class whenRequestingAccessibleAuthorityIsNotNull extends ScopeRegisterAssertSetup {

                @Override
                protected OAuth2ScopeRegisterRequest registerRequest() {
                    return new OAuth2ScopeRegisterRequest(ScopeApplicationTestHelper.RAW_SCOPE_ID, ScopeApplicationTestHelper.DESCRIPTION, ScopeApplicationTestHelper.RAW_AUTHORITIES);
                }

                @Test
                @DisplayName("요청 받은 접근 권한을 유효성 검사 후 저장해야 한다.")
                void shouldSaveAccessibleAuthorityAfterValidation() {
                    ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

                    service.registerNewScope(registerRequest);
                    verifySaveAfterValidation(accessibleAuthorityRule, scopeCaptor);
                    Assertions.assertEquals(ScopeApplicationTestHelper.AUTHORITIES, scopeCaptor.getValue().getAccessibleAuthority());
                }
            }
        }
    }

    @Nested
    @DisplayName("스코프 수정")
    class ModifyScope {

        @BeforeEach
        void setup() {
        }

        @Nested
        @DisplayName("수정할 스코프가 저장소에 저장되어 있지 않을시")
        class WhenModifyScopeNotRegisteredInRepository {
            private OAuth2ScopeModifyRequest request;

            private DefaultScopeDetailsService service;

            @BeforeEach
            void setup() {
                this.request = new OAuth2ScopeModifyRequest(ScopeApplicationTestHelper.NEW_DESCRIPTION, ScopeApplicationTestHelper.RAW_REMOVE_AUTHORITIES, ScopeApplicationTestHelper.RAW_NEW_AUTHORITIES);

                OAuth2ScopeRepository repository = ScopeApplicationTestHelper.mockScopeRepository().emptyScope().build();
                this.service = new DefaultScopeDetailsService(repository);
            }

            @Test
            @DisplayName("ScopeNotFoundException 이 발생해야 한다.")
            void shouldThrowsScopeNotFoundException() {
                assertThrows(ScopeNotFoundException.class, () -> service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, request));
            }
        }

        @Nested
        @DisplayName("수정할 스코프가 저장소에 저장되어 있을시")
        class WhenModifyScopeRegisteredInRepository {

            @Nested
            @DisplayName("삭제할 접근 권한이 null 일시")
            class WhenRequestingRemoveAuthorityIsNull extends ModifyScopeAssertSetup {

                @Override
                protected OAuth2ScopeModifyRequest modifyRequest() {
                    return new OAuth2ScopeModifyRequest(ScopeApplicationTestHelper.NEW_DESCRIPTION, null, ScopeApplicationTestHelper.RAW_NEW_AUTHORITIES);
                }

                @Test
                @DisplayName("스코프에서 접근 권한을 삭제하지 않아야 한다.")
                void shouldNotRemoveAuthorityInScope() {
                    service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, this.request);

                    verify(scope, never()).removeAccessibleAuthority(any());
                }
            }

            @Nested
            @DisplayName("삭제할 접근 권한이 null 이 아닐시")
            class WhenRequestingRemoveAuthorityIsNotNull extends ModifyScopeAssertSetup {

                @Override
                protected OAuth2ScopeModifyRequest modifyRequest() {
                    return new OAuth2ScopeModifyRequest(ScopeApplicationTestHelper.NEW_DESCRIPTION, ScopeApplicationTestHelper.RAW_REMOVE_AUTHORITIES, ScopeApplicationTestHelper.RAW_NEW_AUTHORITIES);
                }

                @Test
                @DisplayName("스코프에서 접근 권한을 삭제하고 유효성 검사를 해야 한다.")
                void shouldValidationAfterRemoveAuthority() {
                    InOrder inOrder = inOrder(scope);

                    service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, this.request);
                    ScopeApplicationTestHelper.REMOVE_AUTHORITIES.forEach(auth -> inOrder.verify(scope, times(1)).removeAccessibleAuthority(auth));
                    inOrder.verify(scope, times(1)).validate(policy);
                }
            }

            @Nested
            @DisplayName("추가할 접근 권한이 null 일시")
            class WhenRequestingNewAuthorityIsNull extends ModifyScopeAssertSetup {

                @Override
                protected OAuth2ScopeModifyRequest modifyRequest() {
                    return new OAuth2ScopeModifyRequest(ScopeApplicationTestHelper.NEW_DESCRIPTION, ScopeApplicationTestHelper.RAW_REMOVE_AUTHORITIES, null);
                }

                @Test
                @DisplayName("스코프에서 접근 권한을 추가하지 않아야 한다.")
                void shouldNotAddAuthorityInScope() {
                    service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, request);

                    verify(scope, never()).addAccessibleAuthority(any());
                }
            }

            @Nested
            @DisplayName("추가할 접근 권한이 null 이 아닐시")
            class WhenRequestingNewAuthorityIsNotNull extends ModifyScopeAssertSetup {

                @Override
                protected OAuth2ScopeModifyRequest modifyRequest() {
                    return new OAuth2ScopeModifyRequest(ScopeApplicationTestHelper.NEW_DESCRIPTION, ScopeApplicationTestHelper.RAW_REMOVE_AUTHORITIES, ScopeApplicationTestHelper.RAW_NEW_AUTHORITIES);
                }

                @Test
                @DisplayName("스코프에서 접근 권한을 추가 유효성 검사를 해야 한다.")
                void shouldValidationAfterAddAuthority() {
                    InOrder inOrder = inOrder(scope);

                    service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, this.request);
                    ScopeApplicationTestHelper.NEW_AUTHORITIES.forEach(auth -> inOrder.verify(scope, times(1)).addAccessibleAuthority(auth));
                    inOrder.verify(scope, times(1)).validate(policy);
                }
            }
        }
    }

    @Nested
    @DisplayName("스코프 삭제")
    class RemoveScope {

        @Nested
        @DisplayName("삭제할 스코프가 저장소에 저장되어 있지 않을시")
        class WhenRemoveScopeNotRegisteredInRepository {
            private DefaultScopeDetailsService service;

            @BeforeEach
            void setup() {
                OAuth2ScopeRepository repository = ScopeApplicationTestHelper.mockScopeRepository().emptyScope().build();
                this.service = new DefaultScopeDetailsService(repository);
            }

            @Test
            @DisplayName("ScopeNotFoundException 이 발생해야 한다.")
            void shouldThrowsScopeNotFoundException() {
                assertThrows(ScopeNotFoundException.class, () -> service.removeScope(ScopeApplicationTestHelper.RAW_SCOPE_ID));
            }
        }

        @Nested
        @DisplayName("삭제할 스코프가 저장소에 저장되어 있을시")
        class WhenRemoveScopeRegisteredInRepository {
            private OAuth2Scope scope;
            private OAuth2ScopeRepository repository;

            private DefaultScopeDetailsService service;

            @BeforeEach
            void setup() {
                this.scope = ScopeApplicationTestHelper.mockScope().configDefault().build();
                this.repository = ScopeApplicationTestHelper.mockScopeRepository().registerScope(scope).build();
                this.service = new DefaultScopeDetailsService(repository);
            }

            @Test
            @DisplayName("검색된 스코프를 저장소에서 삭제해야 한다.")
            void shouldRemoveSearchedScope() {
                service.removeScope(ScopeApplicationTestHelper.RAW_SCOPE_ID);

                verify(repository, times(1)).delete(scope);
            }
        }
    }

    private static abstract class ScopeRegisterAssertSetup {
        protected ValidationRule<OAuth2Scope> scopeIdRule;
        protected ValidationRule<OAuth2Scope> accessibleAuthorityRule;
        protected OAuth2ScopeRepository repository;
        protected OAuth2ScopeRegisterRequest registerRequest;

        protected DefaultScopeDetailsService service;

        @BeforeEach
        void setup() {
            this.scopeIdRule = ScopeApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
            this.accessibleAuthorityRule = ScopeApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
            this.repository = ScopeApplicationTestHelper.mockScopeRepository().emptyScope().build();
            this.registerRequest = registerRequest();

            OAuth2ScopeValidationPolicy policy = ScopeApplicationTestHelper.mockValidationPolicy()
                    .scopeIdRule(scopeIdRule).accessibleAuthorityRule(accessibleAuthorityRule).build();

            this.service = new DefaultScopeDetailsService(repository);
            this.service.setValidationPolicy(policy);
        }

        protected abstract OAuth2ScopeRegisterRequest registerRequest();

        @Test
        @DisplayName("요청 받은 스코프 아이디의 유효성을 검사 후 저장 해야 한다.")
        void shouldSaveScopeIdAfterValidation() {
            ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

            service.registerNewScope(registerRequest);
            verifySaveAfterValidation(scopeIdRule, scopeCaptor);
            Assertions.assertEquals(ScopeApplicationTestHelper.SCOPE_ID, scopeCaptor.getValue().getCode());
        }

        @Test
        @DisplayName("요청 받은 스코프 설명을 저장해야 한다.")
        void shouldSaveScopeDescription() {
            ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

            service.registerNewScope(registerRequest);
            verify(repository, times(1)).save(scopeCaptor.capture());
            Assertions.assertEquals(ScopeApplicationTestHelper.DESCRIPTION, scopeCaptor.getValue().getDescription());
        }

        protected void verifySaveAfterValidation(ValidationRule<OAuth2Scope> rule, ArgumentCaptor<OAuth2Scope> argumentCaptor) {
            InOrder inOrder = inOrder(rule, repository);
            inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
            inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
            assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
        }
    }

    private static abstract class ModifyScopeAssertSetup {
        protected OAuth2ScopeModifyRequest request;
        protected OAuth2ScopeValidationPolicy policy;
        protected OAuth2ScopeRepository repository;
        protected OAuth2Scope scope;

        protected DefaultScopeDetailsService service;

        @BeforeEach
        void setup() {
            this.scope = ScopeApplicationTestHelper.mockScope().configDefault().build();
            this.policy = ScopeApplicationTestHelper.mockValidationPolicy().build();
            this.repository = ScopeApplicationTestHelper.mockScopeRepository().registerScope(scope).build();
            this.service = new DefaultScopeDetailsService(repository);
            this.service.setValidationPolicy(policy);

            this.request = modifyRequest();
        }

        @Test
        @DisplayName("요청 받은 권한 설명으로 변경 후 저장해야 한다.")
        void shouldChangeDescriptionToRequestingDescription() {
            InOrder inOrder = inOrder(scope, repository);

            service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, request);
            inOrder.verify(scope, times(1)).setDescription(ScopeApplicationTestHelper.NEW_DESCRIPTION);
            inOrder.verify(repository, times(1)).save(scope);
        }

        @Test
        @DisplayName("스코프의 유효성을 검사 한 후 저장소에 저장해야 한다.")
        void shouldSaveInRepositoryAfterValidation() {
            InOrder inOrder = inOrder(scope, repository);

            service.modifyScope(ScopeApplicationTestHelper.RAW_SCOPE_ID, request);
            inOrder.verify(scope, times(1)).validate(policy);
            inOrder.verify(repository, times(1)).save(scope);
        }

        protected abstract OAuth2ScopeModifyRequest modifyRequest();
    }
}