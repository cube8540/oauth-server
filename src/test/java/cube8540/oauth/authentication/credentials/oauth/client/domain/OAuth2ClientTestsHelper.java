package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
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

    static MockPasswordEncoder mockPasswordEncoder() {
        return new MockPasswordEncoder();
    }

    static MocKValidationRule<OAuth2Client> mocKValidationRule() {
        return new MocKValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static class MockPasswordEncoder {
        private PasswordEncoder encoder;

        private MockPasswordEncoder() {
            this.encoder = mock(PasswordEncoder.class);
        }

        MockPasswordEncoder encode() {
            when(encoder.encode(RAW_SECRET)).thenReturn(RAW_ENCODING_SECRET);
            return this;
        }

        MockPasswordEncoder matches() {
            when(encoder.matches(RAW_SECRET, RAW_ENCODING_SECRET)).thenReturn(true);
            return this;
        }

        MockPasswordEncoder mismatches() {
            when(encoder.matches(RAW_SECRET, RAW_ENCODING_SECRET)).thenReturn(false);
            return this;
        }

        PasswordEncoder build() {
            return encoder;
        }
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

    static class MocKValidationRule<T> {
        private ValidationRule<T> validationRule;

        @SuppressWarnings("unchecked")
        private MocKValidationRule() {
            this.validationRule = mock(ValidationRule.class);
        }

        MocKValidationRule<T> configValidationTrue(T target) {
            when(validationRule.isValid(target)).thenReturn(true);
            return this;
        }

        MocKValidationRule<T> configValidationFalse(T target) {
            when(validationRule.isValid(target)).thenReturn(false);
            return this;
        }

        MocKValidationRule<T> error(ValidationError error) {
            when(validationRule.error()).thenReturn(error);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }
}
