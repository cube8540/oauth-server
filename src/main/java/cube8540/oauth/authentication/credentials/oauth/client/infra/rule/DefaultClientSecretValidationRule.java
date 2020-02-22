package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

public class DefaultClientSecretValidationRule implements ValidationRule<OAuth2Client> {

    private static final String PROPERTY = "secret";
    private static final String MESSAGE = "클라이언트으 패스워드를 입력해 주세요.";

    private String property;
    private String message;

    public DefaultClientSecretValidationRule() {
        this(PROPERTY, MESSAGE);
    }

    public DefaultClientSecretValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Client target) {
        return target.getSecret() != null;
    }
}
