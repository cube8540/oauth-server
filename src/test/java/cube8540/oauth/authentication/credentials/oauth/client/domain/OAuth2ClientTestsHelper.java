package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import cube8540.validator.core.Validator;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2ClientTestsHelper {

    static final String RAW_CLIENT_ID = "CLIENT-ID";

    static final String RAW_SECRET = "SECRET";
    static final String RAW_ENCODING_SECRET = "ENCODING-SECRET";
    static final String RAW_CHANGE_SECRET = "CHANGE-SECRET";

    static final String RAW_ADDED_SCOPE = "ADD-SCOPE";
    static final AuthorityCode ADDED_SCOPE = new AuthorityCode(RAW_ADDED_SCOPE);

    static final URI REDIRECT_URI = URI.create("http://localhost:8080");

    static final String ERROR_PROPERTY = "property";
    static final String ERROR_MESSAGE = "message";

    static PasswordEncoder makePasswordEncoder(String secret, String encodingSecret) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(secret)).thenReturn(encodingSecret);
        when(encoder.matches(secret, encodingSecret)).thenReturn(true);

        return encoder;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ClientValidatorFactory makeErrorValidatorFactory(OAuth2Client client) {
        ValidationRule<OAuth2Client> validationRule = mock(ValidationRule.class);
        OAuth2ClientValidatorFactory factory = mock(OAuth2ClientValidatorFactory.class);

        when(validationRule.isValid(client)).thenReturn(false);
        when(validationRule.error()).thenReturn(new ValidationError(ERROR_PROPERTY, ERROR_MESSAGE));

        Validator<OAuth2Client> validator = Validator.of(client)
                .registerRule(validationRule);
        when(factory.createValidator(client)).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ClientValidatorFactory makePassValidatorFactory(OAuth2Client client) {
        ValidationRule<OAuth2Client> validationRule = mock(ValidationRule.class);
        OAuth2ClientValidatorFactory factory = mock(OAuth2ClientValidatorFactory.class);

        when(validationRule.isValid(client)).thenReturn(true);

        Validator<OAuth2Client> validator = Validator.of(client)
                .registerRule(validationRule);
        when(factory.createValidator(client)).thenReturn(validator);

        return factory;
    }
}
