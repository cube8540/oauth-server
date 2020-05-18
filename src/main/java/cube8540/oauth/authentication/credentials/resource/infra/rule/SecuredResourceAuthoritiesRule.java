package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
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
    private AuthorityDetailsService scopeDetailsService;

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

        List<String> targetScopes = target.getAuthorities().stream().map(AuthorityCode::getValue).collect(Collectors.toList());
        return scopeDetailsService.loadAuthorityByAuthorityCodes(targetScopes).stream()
                .map(AuthorityDetails::getCode).map(AuthorityCode::new)
                .collect(Collectors.toSet()).containsAll(target.getAuthorities());
    }
}
