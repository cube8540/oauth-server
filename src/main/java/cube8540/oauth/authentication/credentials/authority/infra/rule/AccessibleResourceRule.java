package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceDetails;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceReadService;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceId;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

import java.util.stream.Collectors;

public class AccessibleResourceRule implements ValidationRule<Authority> {

    public static final String DEFAULT_PROPERTY = "accessibleResources";
    public static final String DEFAULT_MESSAGE = "부여 할 수 없는 자원 아이디 입니다.";

    private String property;
    private String message;

    @Setter
    private SecuredResourceReadService securedResourceReadService;

    public AccessibleResourceRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public AccessibleResourceRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(Authority target) {
        if (target.getAccessibleResources() == null || target.getAccessibleResources().isEmpty()) {
            return true;
        }
        if (securedResourceReadService == null) {
            return false;
        }

        return securedResourceReadService.getResources().stream()
                .map(SecuredResourceDetails::getResourceId).map(SecuredResourceId::new)
                .collect(Collectors.toSet()).containsAll(target.getAccessibleResources());
    }
}
