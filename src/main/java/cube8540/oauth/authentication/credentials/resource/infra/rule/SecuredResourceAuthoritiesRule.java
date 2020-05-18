package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetailsService;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.List;
import java.util.stream.Collectors;

public class SecuredResourceAuthoritiesRule implements ValidationRule<SecuredResource> {

    public static final String DEFAULT_PROPERTY = "authorities";
    public static final String DEFAULT_MESSAGE = "부여할 수 없는 스코프 입니다.";

    private String property;
    private String message;

    @Setter
    private OAuth2ScopeDetailsService scopeDetailsService;

    public SecuredResourceAuthoritiesRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public SecuredResourceAuthoritiesRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(SecuredResource target) {
        if (target.getAuthorities() == null || target.getAuthorities().isEmpty()) {
            return true;
        }
        if (scopeDetailsService == null) {
            return false;
        }

        List<String> targetScopes = target.getAuthorities().stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());
        return scopeDetailsService.loadScopeDetailsByScopeIds(targetScopes).stream()
                .map(OAuth2ScopeDetails::getScopeId).map(OAuth2ScopeId::new)
                .collect(Collectors.toSet()).containsAll(target.getAuthorities());
    }
}
