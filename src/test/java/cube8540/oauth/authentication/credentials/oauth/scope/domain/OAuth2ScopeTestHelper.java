package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2ScopeTestHelper {

    static final String RAW_SCOPE_ID = "OAUTH2_SCOPE";
    static final String DESCRIPTION = "DESCRIPTION";

    static final String RAW_AUTHORITY_CODE = "AUTHORITY-CODE";
    static final AuthorityCode AUTHORITY_CODE = new AuthorityCode(RAW_AUTHORITY_CODE);

    static final Set<String> RAW_ACCESSIBLE_AUTHORITY = new HashSet<>(Arrays.asList("AUTHORITY-CODE-1", "AUTHORITY-CODE-2", "AUTHORITY-CODE-3"));
    static final Set<AuthorityCode> ACCESSIBLE_AUTHORITY = RAW_ACCESSIBLE_AUTHORITY.stream().map(AuthorityCode::new).collect(Collectors.toSet());

    static final Collection<? extends GrantedAuthority> GRANTED_AUTHORITIES = RAW_ACCESSIBLE_AUTHORITY.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
    static final Collection<? extends GrantedAuthority> NOT_ACCESSIBLE_AUTHORITIES = new HashSet<>(Arrays.asList(
            new SimpleGrantedAuthority("AUTHORITY-CODE-4"), new SimpleGrantedAuthority("AUTHORITY-CODE-5"), new SimpleGrantedAuthority("AUTHORITY-CODE-6")));

    static Authentication makeAuthentication(Collection<? extends GrantedAuthority> grantedAuthorities) {
        Authentication authentication = mock(Authentication.class);
        doReturn(grantedAuthorities).when(authentication).getAuthorities();
        return authentication;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<OAuth2Scope> makePassValidationRule(OAuth2Scope scope) {
        ValidationRule<OAuth2Scope> validationRule = mock(ValidationRule.class);

        when(validationRule.isValid(scope)).thenReturn(true);

        return validationRule;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<OAuth2Scope> makeErrorValidationRule(OAuth2Scope scope, ValidationError error) {
        ValidationRule<OAuth2Scope> validationRule = mock(ValidationRule.class);

        when(validationRule.isValid(scope)).thenReturn(false);
        when(validationRule.error()).thenReturn(error);

        return validationRule;
    }

    static MockValidationPolicy makeValidationPolicy() {
        return new MockValidationPolicy();
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
}
