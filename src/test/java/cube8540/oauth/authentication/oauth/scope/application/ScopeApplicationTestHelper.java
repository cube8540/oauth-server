package cube8540.oauth.authentication.oauth.scope.application;

import cube8540.oauth.authentication.security.AuthorityCode;
import cube8540.oauth.authentication.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.oauth.scope.domain.OAuth2ScopeRepository;

import java.util.Optional;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScopeApplicationTestHelper {

    static final String RAW_SCOPE_ID = "SCOPE-ID";
    static final AuthorityCode SCOPE_ID = new AuthorityCode(RAW_SCOPE_ID);

    static final String DESCRIPTION = "DESCRIPTION";
    static final String NEW_DESCRIPTION = "NEW-DESCRIPTION";

    static OAuth2Scope makeScope() {
        OAuth2Scope scope = mock(OAuth2Scope.class);

        when(scope.getCode()).thenReturn(SCOPE_ID);
        when(scope.getDescription()).thenReturn(DESCRIPTION);

        return scope;
    }

    static OAuth2ScopeRepository makeEmptyScopeRepository() {
        OAuth2ScopeRepository repository = mock(OAuth2ScopeRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

        return repository;
    }

    static OAuth2ScopeRepository makeScopeRepository(AuthorityCode code, OAuth2Scope scope) {
        OAuth2ScopeRepository repository = mock(OAuth2ScopeRepository.class);

        when(repository.countByCode(code)).thenReturn(1L);
        when(repository.findById(code)).thenReturn(Optional.of(scope));
        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));

        return repository;
    }
}
