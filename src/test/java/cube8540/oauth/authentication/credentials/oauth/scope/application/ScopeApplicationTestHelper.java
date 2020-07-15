package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.validator.core.ValidationRule;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

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

    static final Set<AuthorityCode> AUTHORITIES = new HashSet<>(Arrays.asList(new AuthorityCode("AUTH-CODE-1"), new AuthorityCode("AUTH-CODE-2"),new AuthorityCode("AUTH-CODE-3")));
    static final List<String> RAW_AUTHORITIES = AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());

    static final List<AuthorityCode> NEW_AUTHORITIES = Arrays.asList(new AuthorityCode("NEW-AUTH-1"), new AuthorityCode("NEW-AUTH-2"), new AuthorityCode("NEW-AUTH-3"));
    static final List<String> RAW_NEW_AUTHORITIES = NEW_AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());

    static final List<AuthorityCode> REMOVE_AUTHORITIES = Arrays.asList(new AuthorityCode("REMOVE-AUTH-1"), new AuthorityCode("REMOVE-AUTH-2"), new AuthorityCode("REMOVE-AUTH-3"));
    static final List<String> RAW_REMOVE_AUTHORITIES = REMOVE_AUTHORITIES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());

    static OAuth2Scope makeScope() {
        OAuth2Scope scope = mock(OAuth2Scope.class);

        when(scope.getCode()).thenReturn(SCOPE_ID);
        when(scope.getDescription()).thenReturn(DESCRIPTION);
        when(scope.getAccessibleAuthority()).thenReturn(AUTHORITIES);

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

    @SuppressWarnings("unchecked")
    static OAuth2ScopeValidationPolicy makeValidationPolicy() {
        ValidationRule<OAuth2Scope> scopeIdRule = mock(ValidationRule.class);
        ValidationRule<OAuth2Scope> accessibleRule = mock(ValidationRule.class);
        OAuth2ScopeValidationPolicy policy = mock(OAuth2ScopeValidationPolicy.class);

        when(scopeIdRule.isValid(isA(OAuth2Scope.class))).thenReturn(true);
        when(accessibleRule.isValid(isA(OAuth2Scope.class))).thenReturn(true);
        when(policy.scopeIdRule()).thenReturn(scopeIdRule);
        when(policy.accessibleRule()).thenReturn(accessibleRule);

        return policy;
    }
}
