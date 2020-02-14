package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 스코프 디테일 서비스 테스트")
class DefaultScopeDetailsServiceTest {

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
}