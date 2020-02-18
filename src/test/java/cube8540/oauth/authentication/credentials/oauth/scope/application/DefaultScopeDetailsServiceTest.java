package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeAlreadyExistsException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 스코프 디테일 서비스 테스트")
class DefaultScopeDetailsServiceTest {

    private static final String RAW_SCOPE_ID = "SCOPE";
    private static final OAuth2ScopeId SCOPE_ID = new OAuth2ScopeId(RAW_SCOPE_ID);

    private static final String DESCRIPTION = "DESCRIPTION";
    private static final String MODIFY_DESCRIPTION = "MODIFY-DESCRIPTION";

    private static final Set<AuthorityCode> AUTHORITIES = new HashSet<>(Arrays.asList(new AuthorityCode("AUTH-CODE-1"), new AuthorityCode("AUTH-CODE-2"),new AuthorityCode("AUTH-CODE-3")));
    private static final List<AuthorityCode> NEW_AUTHORITIES = Arrays.asList(new AuthorityCode("NEW-AUTH-1"), new AuthorityCode("NEW-AUTH-2"), new AuthorityCode("NEW-AUTH-3"));
    private static final List<AuthorityCode> REMOVE_AUTHORITIES = Arrays.asList(new AuthorityCode("REMOVE-AUTH-1"), new AuthorityCode("REMOVE-AUTH-2"), new AuthorityCode("REMOVE-AUTH-3"));
    private static final List<String> RAW_AUTHORITIES = AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());
    private static final List<String> RAW_NEW_AUTHORITIES = NEW_AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());
    private static final List<String> RAW_REMOVE_AUTHORITIES = REMOVE_AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());

    private OAuth2ScopeRepository repository;
    private DefaultScopeDetailsService service;

    @BeforeEach
    void setup() {
        this.repository = mock(OAuth2ScopeRepository.class);
        this.service = new DefaultScopeDetailsService(repository);
    }

    @Nested
    @DisplayName("스코프 상세 검색")
    class LookupScopes {

        @Nested
        @DisplayName("검색 결과가 없을시")
        class WhenSearchResultIsEmpty {

            private Collection<String> parameters = Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3");

            @BeforeEach
            void setup() {
                List<OAuth2ScopeId> scopeIdParameters = this.parameters.stream().map(OAuth2ScopeId::new).collect(Collectors.toList());
                when(repository.findByIdIn(scopeIdParameters)).thenReturn(Collections.emptyList());
            }

            @Test
            @DisplayName("빈 리스트가 반환되어야 한다.")
            void shouldReturnsEmptyList() {
                Collection<OAuth2ScopeDetails> results = service.loadScopeDetailsByScopeIds(parameters);

                assertEquals(Collections.emptyList(), results);
            }
        }

        @Nested
        @DisplayName("검색 결과가 1개 이상일시")
        class WhenSearchResultIsNotEmpty {

            private Collection<String> parameters = Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3");
            private List<OAuth2Scope> SCOPES = Arrays.asList(
                    mocking("SCOPE-1", "DESCRIPTION-1"),
                    mocking("SCOPE-2", "DESCRIPTION-2"),
                    mocking("SCOPE-3", "DESCRIPTION-3"));

            @BeforeEach
            void setup() {
                List<OAuth2ScopeId> scopeIdParameters = this.parameters.stream().map(OAuth2ScopeId::new).collect(Collectors.toList());
                when(repository.findByIdIn(scopeIdParameters)).thenReturn(SCOPES);
            }

            @Test
            @DisplayName("저장소 스코프의 정보를 반환해야 한다.")
            void shouldReturnsScopeDetails() {
                Collection<OAuth2ScopeDetails> results = service.loadScopeDetailsByScopeIds(parameters);

                Collection<OAuth2ScopeDetails> expected = SCOPES.stream().map(DefaultOAuth2ScopeDetails::new).collect(Collectors.toList());
                assertEquals(expected, results);
            }

            private OAuth2Scope mocking(String id, String description) {
                OAuth2Scope scope = mock(OAuth2Scope.class);

                when(scope.getId()).thenReturn(new OAuth2ScopeId(id));
                when(scope.getDescription()).thenReturn(description);
                return scope;
            }
        }
    }

    @Nested
    @DisplayName("접근 가능한 스코프 읽기")
    class ReadAccessibleScope {

        private Authentication authentication;
        private List<OAuth2Scope> accessibleScopes;

        @BeforeEach
        void setup() {
            this.authentication = mock(Authentication.class);
            this.accessibleScopes = Arrays.asList(mocking("SCOPE-1", authentication, true),
                    mocking("SCOPE-2", authentication, true),
                    mocking("SCOPE-3", authentication, true));
            List<OAuth2Scope> cannotAccessibleScopes = Arrays.asList(mocking("SCOPE-4", authentication, false),
                    mocking("SCOPE-5", authentication, false),
                    mocking("SCOPE-6", authentication, false));

            when(repository.findAll()).thenReturn(Stream.concat(accessibleScopes.stream(), cannotAccessibleScopes.stream()).collect(Collectors.toList()));
        }

        @Test
        @DisplayName("저장소에서 반환된 스코프중 접근 가능한 스코프만 반환해야 한다.")
        void shouldReturnsCanAccessibleScopes() {
            Collection<OAuth2ScopeDetails> scopes = service.readAccessibleScopes(authentication);

            List<OAuth2ScopeDetails> expected = this.accessibleScopes.stream()
                    .map(DefaultOAuth2ScopeDetails::new).collect(Collectors.toList());
            assertEquals(expected, scopes);
        }

        private OAuth2Scope mocking(String scopeId, Authentication authentication, boolean accessible) {
            OAuth2Scope scope = mock(OAuth2Scope.class);

            when(scope.getId()).thenReturn(new OAuth2ScopeId(scopeId));
            when(scope.isAccessible(authentication)).thenReturn(accessible);
            return scope;
        }
    }

    @Nested
    @DisplayName("새 스코프 등록")
    class RegisterNewScope {
        private OAuth2ScopeRegisterRequest request;

        @BeforeEach
        void setup() {
            this.request = new OAuth2ScopeRegisterRequest(RAW_SCOPE_ID, DESCRIPTION, RAW_AUTHORITIES);
        }

        @Nested
        @DisplayName("저장소에 이미 저장되어 있는 스코프 일시")
        class WhenExistingScopeInRepository {

            @BeforeEach
            void setup() {
                when(repository.countById(SCOPE_ID)).thenReturn(1L);
            }

            @Test
            @DisplayName("OAuth2ScopeAlreadyExistsException이 발생해야 한다.")
            void shouldThrowOAuth2ScopeAlreadyExistsException() {
                assertThrows(OAuth2ScopeAlreadyExistsException.class, () -> service.registerNewScope(request));
            }
        }

        @Nested
        @DisplayName("저장소에 없는 스코프일시")
        class WhenNotExistingScopeId {

            private ValidationRule<OAuth2Scope> scopeIdRule;
            private ValidationRule<OAuth2Scope> accessibleRule;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                OAuth2ScopeValidationPolicy policy = mock(OAuth2ScopeValidationPolicy.class);

                this.scopeIdRule = mock(ValidationRule.class);
                this.accessibleRule = mock(ValidationRule.class);

                when(policy.scopeIdRule()).thenReturn(scopeIdRule);
                when(policy.accessibleRule()).thenReturn(accessibleRule);

                when(scopeIdRule.isValid(any())).thenReturn(true);
                when(accessibleRule.isValid(any())).thenReturn(true);

                when(repository.countById(SCOPE_ID)).thenReturn(0L);
                doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

                service.setValidationPolicy(policy);
            }

            @Test
            @DisplayName("요청 받은 스코프 아이디의 유효성을 검사 후 저장 해야 한다.")
            void shouldSaveScopeIdAfterValidation() {
                ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);
                InOrder inOrder = inOrder(scopeIdRule, repository);

                service.registerNewScope(request);
                inOrder.verify(scopeIdRule, times(1)).isValid(scopeCaptor.capture());
                inOrder.verify(repository, times(1)).save(scopeCaptor.capture());
                assertEquals(scopeCaptor.getAllValues().get(0), scopeCaptor.getAllValues().get(1));
                assertEquals(SCOPE_ID, scopeCaptor.getValue().getId());
            }

            @Test
            @DisplayName("요청 받은 스코프 설명을 저장해야 한다.")
            void shouldSaveScopeDescription() {
                ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);

                service.registerNewScope(request);
                verify(repository, times(1)).save(scopeCaptor.capture());
                assertEquals(DESCRIPTION, scopeCaptor.getValue().getDescription());
            }

            @Test
            @DisplayName("요청 받은 접근 권한을 유효성 검사 후 저장해야 한다.")
            void shouldSaveAccessibleAuthorityAfterValidation() {
                ArgumentCaptor<OAuth2Scope> scopeCaptor = ArgumentCaptor.forClass(OAuth2Scope.class);
                InOrder inOrder = inOrder(accessibleRule, repository);

                service.registerNewScope(request);
                inOrder.verify(accessibleRule, times(1)).isValid(scopeCaptor.capture());
                inOrder.verify(repository, times(1)).save(scopeCaptor.capture());
                assertEquals(scopeCaptor.getAllValues().get(0), scopeCaptor.getAllValues().get(1));
                assertEquals(AUTHORITIES, scopeCaptor.getValue().getAccessibleAuthority());
            }
        }
    }

    @Nested
    @DisplayName("스코프 수정")
    class ModifyScope {
        private OAuth2ScopeModifyRequest request;

        @BeforeEach
        void setup() {
            this.request = new OAuth2ScopeModifyRequest(MODIFY_DESCRIPTION, RAW_REMOVE_AUTHORITIES, RAW_NEW_AUTHORITIES);
        }

        @Nested
        @DisplayName("수정할 스코프가 저장소에 저장되어 있지 않을시")
        class WhenModifyScopeNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findById(SCOPE_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("OAuth2ScopeNotFoundException이 발생해야 한다.")
            void shouldThrowsOAuth2ScopeNotFoundException() {
                assertThrows(OAuth2ScopeNotFoundException.class, () -> service.modifyScope(RAW_SCOPE_ID, request));
            }
        }

        @Nested
        @DisplayName("수정할 스코프가 저장소에 저장되어 있을시")
        class WhenModifyScopeRegisteredInRepository {

            private OAuth2Scope scope;
            private OAuth2ScopeValidationPolicy policy;

            @BeforeEach
            void setup() {
                this.scope = mock(OAuth2Scope.class);
                this.policy = mock(OAuth2ScopeValidationPolicy.class);

                when(scope.getId()).thenReturn(SCOPE_ID);
                when(scope.getDescription()).thenReturn(DESCRIPTION);
                when(scope.getAccessibleAuthority()).thenReturn(AUTHORITIES);
                when(repository.findById(SCOPE_ID)).thenReturn(Optional.of(scope));

                doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

                service.setValidationPolicy(policy);
            }

            @Test
            @DisplayName("요청 받은 권한 설명으로 변경 후 저장해야 한다.")
            void shouldChangeDescriptionToRequestingDescription() {
                InOrder inOrder = inOrder(scope, repository);

                service.modifyScope(RAW_SCOPE_ID, request);
                inOrder.verify(scope, times(1)).setDescription(MODIFY_DESCRIPTION);
                inOrder.verify(repository, times(1)).save(scope);
            }

            @Test
            @DisplayName("삭제할 접근 권한을 삭제하고 새 접근 권한을 저장 한 후 유효성을 검사해야 한다.")
            void shouldValidationAfterRemoveRequestingRemoveAuthorityAndAddRequestingNewAuthority() {
                InOrder inOrder = inOrder(scope, repository);

                service.modifyScope(RAW_SCOPE_ID, request);
                REMOVE_AUTHORITIES.forEach(authority -> inOrder.verify(scope, times(1)).removeAccessibleAuthority(authority));
                NEW_AUTHORITIES.forEach(authority -> inOrder.verify(scope, times(1)).addAccessibleAuthority(authority));
                inOrder.verify(scope, times(1)).validate(policy);
            }

            @Test
            @DisplayName("스코프의 유효성을 검사 한 후 저장소에 저장해야 한다.")
            void shouldSaveInRepositoryAfterValidation() {
                InOrder inOrder = inOrder(scope, repository);

                service.modifyScope(RAW_SCOPE_ID, request);
                inOrder.verify(scope, times(1)).validate(policy);
                inOrder.verify(repository, times(1)).save(scope);
            }
        }
    }

    @Nested
    @DisplayName("스코프 삭제")
    class RemoveScope {

        @Nested
        @DisplayName("삭제할 스코프가 저장소에 저장되어 있지 않을시")
        class WhenRemoveScopeNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findById(SCOPE_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("OAuth2ScopeNotFoundException이 발생해야 한다.")
            void shouldThrowOAuth2ScopeNotFoundException() {
                assertThrows(OAuth2ScopeNotFoundException.class, () -> service.removeScope(RAW_SCOPE_ID));
            }
        }

        @Nested
        @DisplayName("삭제할 스코프가 저장소에 저장되어 있을시")
        class WhenRemoveScopeRegisteredInRepository {

            private OAuth2Scope scope;

            @BeforeEach
            void setup() {
                this.scope = mock(OAuth2Scope.class);

                when(scope.getId()).thenReturn(SCOPE_ID);
                when(scope.getDescription()).thenReturn(DESCRIPTION);
                when(scope.getAccessibleAuthority()).thenReturn(AUTHORITIES);
                when(repository.findById(SCOPE_ID)).thenReturn(Optional.of(scope));
            }

            @Test
            @DisplayName("검색된 스코프를 저장소에서 삭제해야 한다.")
            void shouldRemoveSearchedScope() {
                service.removeScope(RAW_SCOPE_ID);

                verify(repository, times(1)).delete(scope);
            }
        }
    }
}