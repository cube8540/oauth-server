package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
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

    static PasswordEncoder makePasswordEncoder(String secret, String encodingSecret) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(secret)).thenReturn(encodingSecret);
        when(encoder.matches(secret, encodingSecret)).thenReturn(true);

        return encoder;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<OAuth2Client> makePassValidationRule(OAuth2Client client) {
        ValidationRule<OAuth2Client> rule = mock(ValidationRule.class);

        when(rule.isValid(client)).thenReturn(true);

        return rule;
    }

    @SuppressWarnings("unchecked")
    static ValidationRule<OAuth2Client> makeErrorValidationRule(OAuth2Client client, ValidationError error) {
        ValidationRule<OAuth2Client> rule = mock(ValidationRule.class);

        when(rule.isValid(client)).thenReturn(false);
        when(rule.error()).thenReturn(error);

        return rule;
    }

    static MockValidationPolicy makeValidationPolicy() {
        return new MockValidationPolicy();
    }

    static class MockValidationPolicy {
        private OAuth2ClientValidatePolicy policy;

        private MockValidationPolicy() {
            this.policy = mock(OAuth2ClientValidatePolicy.class);
        }

        MockValidationPolicy clientIdRule(ValidationRule<OAuth2Client> clientIdRule) {
            when(policy.clientIdRule()).thenReturn(clientIdRule);
            return this;
        }

        MockValidationPolicy secretRule(ValidationRule<OAuth2Client> secretRule) {
            when(policy.secretRule()).thenReturn(secretRule);
            return this;
        }

        MockValidationPolicy clientNameRule(ValidationRule<OAuth2Client> clientNameRule) {
            when(policy.clientNameRule()).thenReturn(clientNameRule);
            return this;
        }

        MockValidationPolicy grantTypeRule(ValidationRule<OAuth2Client> grantTypeRule) {
            when(policy.grantTypeRule()).thenReturn(grantTypeRule);
            return this;
        }

        MockValidationPolicy scopeRule(ValidationRule<OAuth2Client> scopeRule) {
            when(policy.scopeRule()).thenReturn(scopeRule);
            return this;
        }

        MockValidationPolicy ownerRule(ValidationRule<OAuth2Client> ownerRule) {
            when(policy.ownerRule()).thenReturn(ownerRule);
            return this;
        }

        OAuth2ClientValidatePolicy build() {
            return policy;
        }
    }
}
