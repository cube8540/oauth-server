package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.validator.core.ValidationRule;

public interface OAuth2ClientValidatePolicy {

    ValidationRule<OAuth2Client> clientIdRule();

    ValidationRule<OAuth2Client> secretRule();

    ValidationRule<OAuth2Client> ownerRule();

    ValidationRule<OAuth2Client> clientNameRule();

    ValidationRule<OAuth2Client> grantTypeRule();

    ValidationRule<OAuth2Client> scopeRule();

}
