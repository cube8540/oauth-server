package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.Collection;
import java.util.stream.Collectors;

public class SecuredResourceAuthoritiesRule implements ValidationRule<SecuredResource> {

    public static final String DEFAULT_PROPERTY = "authorities";
    public static final String DEFAULT_MESSAGE = "부여할 수 없는 권한 입니다.";

    private final String property;
    private final String message;
    private final AccessibleAuthority.AuthorityType authorityType;

    @Setter
    private AuthorityDetailsService scopeDetailsService;

    public SecuredResourceAuthoritiesRule(AccessibleAuthority.AuthorityType authorityType) {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE, authorityType);
    }

    public SecuredResourceAuthoritiesRule(String property, String message, AccessibleAuthority.AuthorityType authorityType) {
        this.property = property;
        this.message = message;
        this.authorityType = authorityType;
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
        Collection<String> targetScopes = target.getAuthorities().stream()
                .filter(auth -> auth.getAuthorityType().equals(this.authorityType))
                .map(AccessibleAuthority::getAuthority).collect(Collectors.toSet());

        return scopeDetailsService.loadAuthorityByAuthorityCodes(targetScopes).stream()
                .map(AuthorityDetails::getCode).collect(Collectors.toList()).containsAll(targetScopes);
    }
}
