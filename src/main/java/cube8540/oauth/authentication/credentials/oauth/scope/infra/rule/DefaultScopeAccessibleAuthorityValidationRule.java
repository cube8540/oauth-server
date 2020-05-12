package cube8540.oauth.authentication.credentials.oauth.scope.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetailsService;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.List;
import java.util.stream.Collectors;

public class DefaultScopeAccessibleAuthorityValidationRule implements ValidationRule<OAuth2Scope> {

    private static final String DEFAULT_PROPERTY = "accessibleAuthority";
    private static final String DEFAULT_MESSAGE = "부여할 수 없는 접근 스코프 입니다.";

    private String property;
    private String message;

    @Setter
    private OAuth2ScopeDetailsService scopeDetailsServices;

    public DefaultScopeAccessibleAuthorityValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultScopeAccessibleAuthorityValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Scope target) {
        if (scopeDetailsServices == null) {
            return false;
        }

        List<String> targetScopes = target.getAccessibleAuthority().stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());
        return scopeDetailsServices.loadScopeDetailsByScopeIds(targetScopes).stream()
                .map(OAuth2ScopeDetails::getScopeId).map(OAuth2ScopeId::new)
                .collect(Collectors.toList())
                .containsAll(target.getAccessibleAuthority());
    }
}
