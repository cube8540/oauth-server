package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

public class DefaultOAuth2ClientOwnerValidationRule implements ValidationRule<OAuth2Client> {

    private static final String PROPERTY = "owner";
    private static final String MESSAGE = "클라이언트의 소유자를 입력해 주세요.";

    private String property;
    private String message;

    public DefaultOAuth2ClientOwnerValidationRule() {
        this(PROPERTY, MESSAGE);
    }

    public DefaultOAuth2ClientOwnerValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Client target) {
        return target.getOwner() != null;
    }
}
