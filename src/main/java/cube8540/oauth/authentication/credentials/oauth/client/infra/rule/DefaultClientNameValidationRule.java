package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

public class DefaultClientNameValidationRule implements ValidationRule<OAuth2Client> {

    private static final String DEFAULT_PROPERTY = "clientName";
    private static final String DEFAULT_MESSAGE = "클라이언트명을 입력해 주세요.";

    private String property;
    private String message;

    public DefaultClientNameValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultClientNameValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Client target) {
        return target.getClientName() != null;
    }
}
