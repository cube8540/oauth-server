package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientErrorCodes;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientRegisterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;

import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.CLIENT_NAME;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.ENCODING_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.MODIFY_ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.MODIFY_REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.MODIFY_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.NEW_GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.NEW_REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.NEW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.OWNER;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_OWNER;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.REMOVE_GRANT_TYPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.REMOVE_REDIRECT_URIS;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.REMOVE_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeClientRepository;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeDefaultClient;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeEmptyClientRepository;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeEncoder;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientApplicationTestHelper.makeValidatorFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 클라이언트 관리 서비스 테스트")
class DefaultOAuth2ClientManagementServiceTest {

    @Test
    @DisplayName("이미 등록 되어 있는 클라이언트 등록")
    void registerAlreadyRegisteredClientInRepository() {
        OAuth2Client client = makeDefaultClient();
        OAuth2ClientRepository repository = makeClientRepository(CLIENT_ID, client);
        OAuth2ClientRegisterRequest request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME,
                RAW_REMOVE_REDIRECT_URIS, RAW_SCOPES, RAW_GRANT_TYPES, ACCESS_TOKEN_VALIDITY_SECONDS, REFRESH_TOKEN_VALIDITY_SECONDS, RAW_OWNER);
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        ClientRegisterException e = assertThrows(ClientRegisterException.class, () -> service.registerNewClient(request));
        Assertions.assertEquals(ClientErrorCodes.EXISTS_IDENTIFIER, e.getCode());
    }

    @Test
    @DisplayName("허용 되지 않는 클라이언트 등록")
    void registerNewClientWithInvalidData() {
        OAuth2ClientRegisterRequest request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME,
                RAW_REDIRECT_URIS, RAW_SCOPES, RAW_GRANT_TYPES, ACCESS_TOKEN_VALIDITY_SECONDS, REFRESH_TOKEN_VALIDITY_SECONDS, RAW_OWNER);
        PasswordEncoder encoder = makeEncoder(SECRET, ENCODING_SECRET);
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        OAuth2ClientValidatorFactory factory = makeErrorValidatorFactory(new TestOauth2ClientException());
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        service.setValidateFactory(factory);
        service.setPasswordEncoder(encoder);

        assertThrows(TestOauth2ClientException.class, () -> service.registerNewClient(request));
    }

    @Test
    @DisplayName("새 클라이언트 등록")
    void registerNewClient() {
        ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
        OAuth2ClientRegisterRequest request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME,
                RAW_REDIRECT_URIS, RAW_SCOPES, RAW_GRANT_TYPES, ACCESS_TOKEN_VALIDITY_SECONDS, REFRESH_TOKEN_VALIDITY_SECONDS, RAW_OWNER);
        PasswordEncoder encoder = makeEncoder(SECRET, ENCODING_SECRET);
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        OAuth2ClientValidatorFactory factory = makeValidatorFactory();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        service.setValidateFactory(factory);
        service.setPasswordEncoder(encoder);

        service.registerNewClient(request);
        verify(repository, times(1)).save(clientCaptor.capture());
        assertEquals(CLIENT_ID, clientCaptor.getValue().getClientId());
        assertEquals(ENCODING_SECRET, clientCaptor.getValue().getSecret());
        assertEquals(OWNER, clientCaptor.getValue().getOwner());
        assertEquals(REDIRECT_URIS, clientCaptor.getValue().getRedirectUris());
        assertEquals(SCOPES, clientCaptor.getValue().getScopes());
        assertEquals(GRANT_TYPES, clientCaptor.getValue().getGrantTypes());
        assertEquals(Duration.ofSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), clientCaptor.getValue().getAccessTokenValidity());
        assertEquals(Duration.ofSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), clientCaptor.getValue().getRefreshTokenValidity());
    }

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 클라이언트 수정")
    void modifyNotRegisteredClientInRepository() {
        OAuth2ClientModifyRequest request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS,
                RAW_REMOVE_REDIRECT_URIS, RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES,
                MODIFY_ACCESS_TOKEN_VALIDITY_SECONDS, MODIFY_REFRESH_TOKEN_VALIDITY_SECONDS);
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        assertThrows(ClientNotFoundException.class, () -> service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request));
    }

    @Test
    @DisplayName("클라이언트 수정")
    void modifyClient() {
        OAuth2Client client = makeDefaultClient();
        OAuth2ClientModifyRequest request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS,
                RAW_REMOVE_REDIRECT_URIS, RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES,
                MODIFY_ACCESS_TOKEN_VALIDITY_SECONDS, MODIFY_REFRESH_TOKEN_VALIDITY_SECONDS);
        OAuth2ClientRepository repository = makeClientRepository(CLIENT_ID, client);
        OAuth2ClientValidatorFactory factory = makeValidatorFactory();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        service.setValidateFactory(factory);

        InOrder inOrder = inOrder(client, repository);
        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
        inOrder.verify(client, times(1)).setClientName(MODIFY_CLIENT_NAME);
        REMOVE_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).removeRedirectUri(uri));
        NEW_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).addRedirectUri(uri));
        REMOVE_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).removeGrantType(grant));
        NEW_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).addGrantType(grant));
        REMOVE_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).removeScope(scope));
        NEW_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).addScope(scope));
        inOrder.verify(client, times(1)).setAccessTokenValidity(MODIFY_ACCESS_TOKEN_VALIDITY_SECONDS);
        inOrder.verify(client, times(1)).setRefreshTokenValidity(MODIFY_REFRESH_TOKEN_VALIDITY_SECONDS);
        inOrder.verify(client, times(1)).validate(factory);
        inOrder.verify(repository, times(1)).save(client);
    }

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 클라이언트 패스워드 변경")
    void changePasswordNotRegisteredClientInRepository() {
        OAuth2ChangeSecretRequest request = new OAuth2ChangeSecretRequest(SECRET, MODIFY_SECRET);
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        assertThrows(ClientNotFoundException.class, () -> service.changeSecret(RAW_CLIENT_ID, request));
    }

    @Test
    @DisplayName("클라이언트 패스워드 변경")
    void changeClientSecret() {
        OAuth2ChangeSecretRequest request = new OAuth2ChangeSecretRequest(SECRET, MODIFY_SECRET);
        OAuth2Client client = makeDefaultClient();
        OAuth2ClientRepository repository = makeClientRepository(CLIENT_ID, client);
        PasswordEncoder encoder = makeEncoder(MODIFY_SECRET, ENCODING_SECRET);
        OAuth2ClientValidatorFactory factory = makeValidatorFactory();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        service.setValidateFactory(factory);
        service.setPasswordEncoder(encoder);

        InOrder inOrder = inOrder(client, repository);
        service.changeSecret(RAW_CLIENT_ID, request);
        inOrder.verify(client, times(1)).changeSecret(SECRET, MODIFY_SECRET, encoder);
        inOrder.verify(client, times(1)).validate(factory);
        inOrder.verify(client, times(1)).encrypted(encoder);
        inOrder.verify(repository, times(1)).save(client);
    }

    @Test
    @DisplayName("저장소에 등록 되어 있지 않은 클라이언트 삭제")
    void removeNotRegisteredClientInRepository() {
        OAuth2ClientRepository repository = makeEmptyClientRepository();
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        assertThrows(ClientNotFoundException.class, () -> service.removeClient(RAW_CLIENT_ID));
    }

    @Test
    @DisplayName("클라이언트 삭제")
    void removeClient() {
        OAuth2Client client = makeDefaultClient();
        OAuth2ClientRepository repository = makeClientRepository(CLIENT_ID, client);
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);

        service.removeClient(RAW_CLIENT_ID);
        verify(repository, times(1)).delete(client);
    }

    @AfterEach
    void after() {
        SecurityContextHolder.clearContext();
    }

    private static class TestOauth2ClientException extends RuntimeException {}
}