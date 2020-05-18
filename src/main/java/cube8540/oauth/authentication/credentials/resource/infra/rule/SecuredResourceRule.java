package cube8540.oauth.authentication.credentials.resource.infra.rule;

import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class SecuredResourceRule implements ValidationRule<SecuredResource> {

    public static final String DEFAULT_PROPERTY = "resource";
    public static final String DEFAULT_MESSAGE = "자원을 입력해 주세요.";

    private String property;
    private String message;

    public SecuredResourceRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(SecuredResource target) {
        return target.getResource() != null;
    }
}
