package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.domain.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientOwner;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatePolicy;
import cube8540.validator.core.ValidationRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2ClientApplicationTestHelper {

    static final String RAW_CLIENT_ID = "CLIENT_ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    static final String SECRET = "SECRET";
    static final String ENCODING_SECRET = "ENCODING-SECRET";
    static final String MODIFY_SECRET = "MODIFY-SECRET";
    static final String ENCODING_MODIFY_SECRET = "ENCODING-MODIFY-SECRET";

    static final String CLIENT_NAME = "CLIENT-NAME";
    static final String MODIFY_CLIENT_NAME = "MODIFY-CLIENT-NAME";

    static final Set<URI> REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080"), URI.create("http://localhost:8081"), URI.create("http://localhost:8082")));
    static final Set<URI> NEW_REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080/new"), URI.create("http://localhost:8081/new"), URI.create("http://localhost:8082/new")));
    static final Set<URI> REMOVE_REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080/remove"), URI.create("http://localhost:8081/remove"), URI.create("http://localhost:8082/remove")));
    static final List<String> RAW_REDIRECT_URIS = REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());
    static final List<String> RAW_NEW_REDIRECT_URIS = NEW_REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());
    static final List<String> RAW_REMOVE_REDIRECT_URIS = REMOVE_REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());

    static final Set<AuthorizationGrantType> GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN));
    static final Set<AuthorizationGrantType> NEW_GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.IMPLICIT, AuthorizationGrantType.CLIENT_CREDENTIALS));
    static final Set<AuthorizationGrantType> REMOVE_GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.PASSWORD, AuthorizationGrantType.REFRESH_TOKEN));
    static final List<String> RAW_GRANT_TYPES = GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
    static final List<String> RAW_NEW_GRANT_TYPES = NEW_GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
    static final List<String> RAW_REMOVE_GRANT_TYPES = REMOVE_GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());

    static final Set<AuthorityCode> SCOPES = new HashSet<>(Arrays.asList(new AuthorityCode("SCOPE-1"), new AuthorityCode("SCOPE-2"), new AuthorityCode("SCOPE-3")));
    static final Set<AuthorityCode> NEW_SCOPES = new HashSet<>(Arrays.asList(new AuthorityCode("NEW-SCOPE-1"), new AuthorityCode("NEW-SCOPE-1"), new AuthorityCode("NEW-SCOPE-1")));
    static final Set<AuthorityCode> REMOVE_SCOPES = new HashSet<>(Arrays.asList(new AuthorityCode("REMOVE-SCOPE-1"), new AuthorityCode("REMOVE-SCOPE-2"), new AuthorityCode("REMOVE-SCOPE-3")));
    static final List<String> RAW_SCOPES = SCOPES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());
    static final List<String> RAW_NEW_SCOPES = NEW_SCOPES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());
    static final List<String> RAW_REMOVE_SCOPES = REMOVE_SCOPES.stream().map(AuthorityCode::getValue).collect(Collectors.toList());

    static final String RAW_OWNER = "owner@email.com";
    static final ClientOwner OWNER = new ClientOwner(RAW_OWNER);

    static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10);
    static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofHours(12);

    static MockOAuth2Client mockOAuth2Client() {
        return new MockOAuth2Client();
    }

    static MockOAuth2ClientRepository mockOAuth2ClientRepository() {
        return new MockOAuth2ClientRepository();
    }

    static MockPasswordEncoder mockPasswordEncoder() {
        return new MockPasswordEncoder();
    }

    static MocKValidationRule<OAuth2Client> mocKValidationRule() {
        return new MocKValidationRule<>();
    }

    static MockValidationPolicy mockValidationPolicy() {
        return new MockValidationPolicy();
    }

    static Authentication mockAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_OWNER);
        return authentication;
    }

    static Authentication mockDifferentAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn("DIFFERENT OWNER");
        return authentication;
    }

    static class MockOAuth2Client {
        private OAuth2Client client;

        private MockOAuth2Client() {
            this.client = mock(OAuth2Client.class);
        }

        MockOAuth2Client configDefault() {
            when(client.getClientId()).thenReturn(CLIENT_ID);
            when(client.getSecret()).thenReturn(ENCODING_SECRET);
            when(client.getClientName()).thenReturn(CLIENT_NAME);
            when(client.getRedirectUris()).thenReturn(REDIRECT_URIS);
            when(client.getGrantTypes()).thenReturn(GRANT_TYPES);
            when(client.getScopes()).thenReturn(SCOPES);
            when(client.getOwner()).thenReturn(OWNER);

            return this;
        }

        OAuth2Client build() {
            return client;
        }
    }

    static class MockOAuth2ClientRepository {
        private OAuth2ClientRepository repository;

        private MockOAuth2ClientRepository() {
            this.repository = mock(OAuth2ClientRepository.class);
            doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));
        }

        MockOAuth2ClientRepository registerClient(OAuth2Client client) {
            when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
            when(repository.countByClientId(CLIENT_ID)).thenReturn(1L);
            return this;
        }

        MockOAuth2ClientRepository emptyClient() {
            when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());
            when(repository.countByClientId(CLIENT_ID)).thenReturn(0L);
            return this;
        }

        OAuth2ClientRepository build() {
            return repository;
        }
    }

    static class MockPasswordEncoder {
        private PasswordEncoder encoder;

        private MockPasswordEncoder() {
            this.encoder = mock(PasswordEncoder.class);
        }

        MockPasswordEncoder encode(String raw, String encoded) {
            when(encoder.encode(raw)).thenReturn(encoded);
            return this;
        }

        MockPasswordEncoder matches(String raw, String encoded) {
            when(encoder.matches(raw, encoded)).thenReturn(true);
            return this;
        }

        MockPasswordEncoder mismatches(String raw, String encoded) {
            when(encoder.matches(raw, encoded)).thenReturn(false);
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

        MocKValidationRule<T> configValidationTrue() {
            when(validationRule.isValid(any())).thenReturn(true);
            return this;
        }

        MocKValidationRule<T> configValidationFalse() {
            when(validationRule.isValid(any())).thenReturn(false);
            return this;
        }

        ValidationRule<T> build() {
            return validationRule;
        }
    }
}
