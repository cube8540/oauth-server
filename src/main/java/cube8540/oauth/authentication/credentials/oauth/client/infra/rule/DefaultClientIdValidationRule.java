package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.regex.Pattern;

public class DefaultClientIdValidationRule implements ValidationRule<OAuth2Client> {

    private static final String WHITELIST_PATTERN_VALUE = "^[_\\-a-zA-Z0-9]+$";

    private static final String DEFAULT_PROPERTY = "clientId";
    private static final String DEFAULT_MESSAGE = "아이디는 8 ~ 30글자 사이의 문자열로 입력해 주세요. (특수문자는 '-', '_' 만 가능합니다.)";

    private String property;
    private String message;

    public DefaultClientIdValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultClientIdValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Client target) {
        String clientId = target.getClientId().getValue();

        return clientId.length() >= 8 && clientId.length() <= 30 &&
                Pattern.compile(WHITELIST_PATTERN_VALUE).matcher(clientId).matches();
    }
}
