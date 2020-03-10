package cube8540.oauth.authentication.credentials.oauth.scope.infra.rule;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.stream.Collectors;

public class DefaultScopeAccessibleAuthorityValidationRule implements ValidationRule<OAuth2Scope> {

    private static final String DEFAULT_PROPERTY = "accessibleAuthority";
    private static final String DEFAULT_MESSAGE = "부여할 수 없는 접근 권한입니다.";

    private String property;
    private String message;

    @Setter
    private AuthorityDetailsService authorityService;

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
        if (authorityService == null) {
            return false;
        }

        return authorityService.getAuthorities().stream()
                .map(AuthorityDetails::getCode).map(AuthorityCode::new)
                .collect(Collectors.toList())
                .containsAll(target.getAccessibleAuthority());
    }
}
