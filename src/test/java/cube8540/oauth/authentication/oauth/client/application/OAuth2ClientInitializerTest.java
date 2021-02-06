package cube8540.oauth.authentication.oauth.client.application;

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.security.AuthorityDetails;
import cube8540.oauth.authentication.security.AuthorityDetailsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.ENCODING_SECRET;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.INITIALIZE_GRANT_TYPE;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.INITIALIZE_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.OWNER;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_INITIALIZE_GRANT;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_INITIALIZE_REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_OWNER;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.SECRET;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeAuthorityDetails;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeClientRepository;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeDefaultClient;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeEmptyClientRepository;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeEncoder;
import static cube8540.oauth.authentication.oauth.client.application.OAuth2ClientApplicationTestHelper.makeInitializerAuthorityDetailsService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 초기화 테스트")
public class OAuth2ClientInitializerTest {
    private static final String USERNAME_KEY = "init-user.username";

    private static final String CLIENT_ID_KEY = "init-oauth-client.client-id";
    private static final String CLIENT_SECRET_KEY = "init-oauth-client.client-secret";
    private static final String CLIENT_NAME = "init-oauth-client.client-name";
    private static final String CLIENT_GRANT_TYPE_KEY = "init-oauth-client.client-grant-type";
    private static final String CLIENT_REDIRECT_URI = "init-oauth-client.client-redirect-uri";

    @Test
    @DisplayName("초기화 클라이언트가 저장소에 있을시")
    void initializeWhenClientIsExists() {
        OAuth2Client client = makeDefaultClient();
        OAuth2ClientRepository repository = makeClientRepository(CLIENT_ID, client);
        PasswordEncoder encoder = makeEncoder(SECRET, ENCODING_SECRET);
        Set<AuthorityDetails> authorityDetails = makeAuthorityDetails(RAW_SCOPES);
        AuthorityDetailsService authorityDetailsService = makeInitializerAuthorityDetailsService(authorityDetails);
        Environment environment = mock(Environment.class);
        OAuth2ClientInitializer initializer = new OAuth2ClientInitializer(repository, encoder, authorityDetailsService);

        when(environment.getRequiredProperty(CLIENT_ID_KEY)).thenReturn(RAW_CLIENT_ID);
        when(environment.getRequiredProperty(CLIENT_SECRET_KEY)).thenReturn(SECRET);
        when(environment.getRequiredProperty(CLIENT_GRANT_TYPE_KEY)).thenReturn(RAW_INITIALIZE_GRANT);
        when(environment.getRequiredProperty(CLIENT_REDIRECT_URI)).thenReturn(RAW_INITIALIZE_REDIRECT_URI);
        when(environment.getRequiredProperty(CLIENT_NAME)).thenReturn(CLIENT_NAME);
        when(environment.getRequiredProperty(USERNAME_KEY)).thenReturn(RAW_OWNER);

        initializer.initialize(environment);
        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("초기화 클라이언트가 저장소에 없을시")
    void initializeWhenClientNotExists() {
        ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        PasswordEncoder encoder = makeEncoder(SECRET, ENCODING_SECRET);
        Set<AuthorityDetails> authorityDetails = makeAuthorityDetails(RAW_SCOPES);
        AuthorityDetailsService authorityDetailsService = makeInitializerAuthorityDetailsService(authorityDetails);
        Environment environment = mock(Environment.class);
        OAuth2ClientInitializer initializer = new OAuth2ClientInitializer(repository, encoder, authorityDetailsService);

        when(environment.getRequiredProperty(CLIENT_ID_KEY)).thenReturn(RAW_CLIENT_ID);
        when(environment.getRequiredProperty(CLIENT_SECRET_KEY)).thenReturn(SECRET);
        when(environment.getRequiredProperty(CLIENT_GRANT_TYPE_KEY)).thenReturn(RAW_INITIALIZE_GRANT);
        when(environment.getRequiredProperty(CLIENT_REDIRECT_URI)).thenReturn(RAW_INITIALIZE_REDIRECT_URI);
        when(environment.getRequiredProperty(CLIENT_NAME)).thenReturn(CLIENT_NAME);
        when(environment.getRequiredProperty(USERNAME_KEY)).thenReturn(RAW_OWNER);

        initializer.initialize(environment);
        verify(repository, times(1)).save(clientCaptor.capture());
        assertEquals(CLIENT_ID, clientCaptor.getValue().getClientId());
        assertEquals(ENCODING_SECRET, clientCaptor.getValue().getSecret());
        assertEquals(CLIENT_NAME, clientCaptor.getValue().getClientName());
        assertEquals(INITIALIZE_GRANT_TYPE, clientCaptor.getValue().getGrantTypes());
        assertEquals(INITIALIZE_REDIRECT_URI, clientCaptor.getValue().getRedirectUris());
        assertEquals(OWNER, clientCaptor.getValue().getOwner());
        assertEquals(SCOPES, clientCaptor.getValue().getScopes());
    }
}
