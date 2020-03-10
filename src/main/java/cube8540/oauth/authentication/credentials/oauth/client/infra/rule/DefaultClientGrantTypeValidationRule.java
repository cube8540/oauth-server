package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

public class DefaultClientGrantTypeValidationRule implements ValidationRule<OAuth2Client> {

    private static final String DEFAULT_PROPERTY = "grantType";
    private static final String DEFAULT_MESSAGE = "클라이언트의 인증 타입은 한개 이상이어야 합니다.";

    private String property;
    private String message;

    public DefaultClientGrantTypeValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultClientGrantTypeValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Client target) {
        return target.getGrantTypes() != null && !target.getGrantTypes().isEmpty();
    }
}
