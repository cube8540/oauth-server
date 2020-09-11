package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.ClientOwner;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatorFactory;
import cube8540.validator.core.ValidationResult;
import cube8540.validator.core.Validator;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
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

    static final Integer ACCESS_TOKEN_VALIDITY_SECONDS = 6000;
    static final Integer REFRESH_TOKEN_VALIDITY_SECONDS = 60000;
    static final Integer MODIFY_ACCESS_TOKEN_VALIDITY_SECONDS = 60000;
    static final Integer MODIFY_REFRESH_TOKEN_VALIDITY_SECONDS = 600000;

    static final String RAW_OWNER = "owner@email.com";
    static final ClientOwner OWNER = new ClientOwner(RAW_OWNER);

    static OAuth2ClientRepository makeEmptyClientRepository() {
        OAuth2ClientRepository repository = mock(OAuth2ClientRepository.class);

        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));

        return repository;
    }

    static OAuth2ClientRepository makeClientRepository(OAuth2ClientId clientId, OAuth2Client client) {
        OAuth2ClientRepository repository = mock(OAuth2ClientRepository.class);

        when(repository.countByClientId(clientId)).thenReturn(1L);
        when(repository.findByClientId(clientId)).thenReturn(Optional.of(client));
        doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));

        return repository;
    }

    static OAuth2Client makeDefaultClient() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(client.getSecret()).thenReturn(ENCODING_SECRET);
        when(client.getClientName()).thenReturn(CLIENT_NAME);
        when(client.getRedirectUris()).thenReturn(REDIRECT_URIS);
        when(client.getGrantTypes()).thenReturn(GRANT_TYPES);
        when(client.getScopes()).thenReturn(SCOPES);
        when(client.getOwner()).thenReturn(OWNER);

        return client;
    }

    static PasswordEncoder makeEncoder(String rawSecret, String encodingSecret) {
        PasswordEncoder encoder = mock(PasswordEncoder.class);

        when(encoder.encode(rawSecret)).thenReturn(encodingSecret);
        when(encoder.matches(rawSecret, encodingSecret)).thenReturn(true);

        return encoder;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ClientValidatorFactory makeValidatorFactory() {
        OAuth2ClientValidatorFactory factory = mock(OAuth2ClientValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<OAuth2Client> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    @SuppressWarnings("unchecked")
    static OAuth2ClientValidatorFactory makeErrorValidatorFactory(Exception exception) {
        OAuth2ClientValidatorFactory factory = mock(OAuth2ClientValidatorFactory.class);
        ValidationResult result = mock(ValidationResult.class);
        Validator<OAuth2Client> validator = mock(Validator.class);

        when(validator.getResult()).thenReturn(result);
        doAnswer(invocation -> {throw exception;}).when(result).hasErrorThrows(any());
        when(factory.createValidator(any())).thenReturn(validator);

        return factory;
    }

    static Authentication makeAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(RAW_OWNER);
        return authentication;
    }

    static Authentication makeDifferentAuthentication() {
        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn("DIFFERENT OWNER");
        return authentication;
    }
}
