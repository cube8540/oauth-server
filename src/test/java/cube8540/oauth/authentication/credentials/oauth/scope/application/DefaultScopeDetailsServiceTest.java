package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

        private Collection<OAuth2Scope> scopes;

        @BeforeEach
        void setup() {
            this.scopes = new ArrayList<>();

            this.scopes.add(mock(OAuth2Scope.class));
            this.scopes.add(mock(OAuth2Scope.class));
            this.scopes.add(mock(OAuth2Scope.class));
        }

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
                Collection<OAuth2ScopeDetails> results = service.loopScopes(parameters);

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
                Collection<OAuth2ScopeDetails> results = service.loopScopes(parameters);

                Collection<OAuth2ScopeDetails> expected = SCOPES.stream().map(DetailsOAuth2ScopeDetails::new).collect(Collectors.toList());
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
}