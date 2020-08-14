package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.validator.core.Validator;

public interface OAuth2ClientValidatorFactory {

    Validator<OAuth2Client> createValidator(OAuth2Client client);

}
