package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.stream.Collectors;

public class SecuredResourceAuthoritiesRule implements ValidationRule<SecuredResource> {

    public static final String DEFAULT_PROPERTY = "authorities";
    public static final String DEFAULT_MESSAGE = "부여할 수 없는 권한 입니다.";

    private String property;
    private String message;

    @Setter
    private AuthorityDetailsService authorityDetailsService;

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
        if (authorityDetailsService == null) {
            return false;
        }

        return authorityDetailsService.getAuthorities().stream()
                .map(AuthorityDetails::getCode).map(AuthorityCode::new)
                .collect(Collectors.toSet()).containsAll(target.getAuthorities());
    }
}
