package cube8540.oauth.authentication.credentials.oauth.scope.application;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeRepository;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
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

    static MockScope mockScope() {
        return new MockScope();
    }

    static MockScopeRepository mockScopeRepository() {
        return new MockScopeRepository();
    }

    static MocKValidationRule<OAuth2Scope> mocKValidationRule() {
        return new MocKValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static class MockScope {
        private OAuth2Scope scope;

        private MockScope() {
            this.scope = mock(OAuth2Scope.class);
        }

        MockScope configDefault() {
            configDefaultScopeId();
            configDefaultDescription();
            configDefaultAccessibleAuthority();
            return this;
        }

        MockScope configDefaultScopeId() {
            when(scope.getCode()).thenReturn(SCOPE_ID);
            return this;
        }

        MockScope configDefaultDescription() {
            when(scope.getDescription()).thenReturn(DESCRIPTION);
            return this;
        }

        MockScope configDefaultAccessibleAuthority() {
            when(scope.getAccessibleAuthority()).thenReturn(AUTHORITIES);
            return this;
        }

        OAuth2Scope build() {
            return scope;
        }
    }

    static class MockScopeRepository {
        private OAuth2ScopeRepository repository;

        private MockScopeRepository() {
            this.repository = mock(OAuth2ScopeRepository.class);
            doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Scope.class));
        }

        MockScopeRepository count(long count) {
            when(repository.countById(SCOPE_ID)).thenReturn(count);
            return this;
        }

        MockScopeRepository registerScope(OAuth2Scope scope) {
            when(repository.findById(SCOPE_ID)).thenReturn(Optional.of(scope));
            when(repository.countById(SCOPE_ID)).thenReturn(1L);
            return this;
        }

        MockScopeRepository emptyScope() {
            when(repository.findById(SCOPE_ID)).thenReturn(Optional.empty());
            when(repository.countById(SCOPE_ID)).thenReturn(0L);
            return this;
        }

        OAuth2ScopeRepository build() {
            return repository;
        }
    }

    static class MockValidationPolicy {
        private OAuth2ScopeValidationPolicy policy;

        private MockValidationPolicy() {
            this.policy = mock(OAuth2ScopeValidationPolicy.class);
        }

        MockValidationPolicy scopeIdRule(ValidationRule<OAuth2Scope> scopeIdRule) {
            when(policy.scopeIdRule()).thenReturn(scopeIdRule);
            return this;
        }

        MockValidationPolicy accessibleAuthorityRule(ValidationRule<OAuth2Scope> accessibleAuthorityRule) {
            when(policy.accessibleRule()).thenReturn(accessibleAuthorityRule);
            return this;
        }

        OAuth2ScopeValidationPolicy build() {
            return policy;
        }
    }

    static class MocKValidationRule<T> {
        private ValidationRule<T> validationRule;

        @SuppressWarnings("unchecked")
        private MocKValidationRule() {
            this.validationRule = mock(ValidationRule.class);
        }

        MocKValidationRule<T> configValidationTrue() {
            when(validationRule.isValid(any())).thenReturn(true);
            return this;
        }

        MocKValidationRule<T> configValidationFalse() {
            when(validationRule.isValid(any())).thenReturn(false);
            return this;
        }

        MocKValidationRule<T> error(ValidationError error) {
            when(validationRule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }
}
