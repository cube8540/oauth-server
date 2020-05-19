package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class SecuredResourceIdRule implements ValidationRule<SecuredResource> {

    public static final String DEFAULT_PROPERTY = "resourceId";
    public static final String DEFAULT_MESSAGE = "자원 아이디를 입력해 주세요.";

    private String property;
    private String message;

    public SecuredResourceIdRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(SecuredResource target) {
        return target.getResourceId() != null && target.getResourceId().getValue() != null;
    }
}
