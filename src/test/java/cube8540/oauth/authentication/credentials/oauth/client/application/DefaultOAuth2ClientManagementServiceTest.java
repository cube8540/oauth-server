package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatePolicy;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientErrorCodes;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientRegisterException;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("기본 클라이언트 관리 서비스 테스트")
class DefaultOAuth2ClientManagementServiceTest {

    @Nested
    @DisplayName("새 클라이언트 추가")
    class RegisterNewClient {

        @Nested
        @DisplayName("저장소에 이미 저장된 클라이언트의 아이디일시")
        class WhenExistingClientIdInRepository {
            private OAuth2ClientRegisterRequest request;

            private DefaultOAuth2ClientManagementService service;

            @BeforeEach
            void setup() {
                this.request = new OAuth2ClientRegisterRequest(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_GRANT_TYPES);
                OAuth2ClientRepository repository = OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository().registerClient(OAuth2ClientApplicationTestHelper.mockOAuth2Client().build()).build();

                this.service = new DefaultOAuth2ClientManagementService(repository);
            }

            @Test
            @DisplayName("ClientRegisterException 이 발생해야 하며 에러 코드는 EXISTS_IDENTIFIER 이어야 한다.")
            void shouldThrowsClientRegisterException() {
                ClientRegisterException e = assertThrows(ClientRegisterException.class, () -> service.registerNewClient(request));
                Assertions.assertEquals(ClientErrorCodes.EXISTS_IDENTIFIER, e.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 없는 클라이언트 아이디일시")
        class WhenNotExistingClientIdInRepository {
            private OAuth2ClientRegisterRequest request;
            private ValidationRule<OAuth2Client> clientIdRule;
            private ValidationRule<OAuth2Client> secretRule;
            private ValidationRule<OAuth2Client> clientNameRule;
            private ValidationRule<OAuth2Client> grantTypeRule;
            private ValidationRule<OAuth2Client> scopeRule;
            private ValidationRule<OAuth2Client> ownerRule;
            private OAuth2ClientRepository repository;

            private DefaultOAuth2ClientManagementService service;

            @BeforeEach
            void setup() {
                this.request = new OAuth2ClientRegisterRequest(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_GRANT_TYPES);
                this.clientIdRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.secretRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.clientNameRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.grantTypeRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.scopeRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.ownerRule = OAuth2ClientApplicationTestHelper.mocKValidationRule().configValidationTrue().build();
                this.repository = OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository().emptyClient().build();

                OAuth2ClientValidatePolicy policy = OAuth2ClientApplicationTestHelper.mockValidationPolicy().clientIdRule(clientIdRule).secretRule(secretRule)
                        .clientNameRule(clientNameRule).grantTypeRule(grantTypeRule).scopeRule(scopeRule).ownerRule(ownerRule).build();

                this.service = new DefaultOAuth2ClientManagementService(repository);
                this.service.setPasswordEncoder(OAuth2ClientApplicationTestHelper.mockPasswordEncoder().encode(OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.ENCODING_SECRET).build());
                this.service.setValidatePolicy(policy);

                SecurityContextHolder.getContext().setAuthentication(OAuth2ClientApplicationTestHelper.mockAuthentication());
            }

            @Test
            @DisplayName("요청 받은 클라이언트 아이디의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientIdAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(clientIdRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.CLIENT_ID, clientCaptor.getValue().getClientId());
            }

            @Test
            @DisplayName("요청 받은 클라이언트 패스워드의 유효성을 검사한 후 암호화 하여 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientSecretAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(secretRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.ENCODING_SECRET, clientCaptor.getValue().getSecret());
            }

            @Test
            @DisplayName("요청 받은 클라이언트명의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientNameAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(clientNameRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.CLIENT_NAME, clientCaptor.getValue().getClientName());
            }

            @Nested
            @DisplayName("요청 받은 권한 부여 방식이 null 일시")
            class WhenRequestingGrantTypeIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_SCOPES, null);
                }

                @Test
                @DisplayName("클라이언트에 권한 부여 방식을 저장하지 않아야 한다.")
                void shouldNotSaveGrantTypeForClient() {
                    ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                    service.registerNewClient(request);
                    verify(repository, times(1)).save(clientCaptor.capture());
                    assertNull(clientCaptor.getValue().getGrantTypes());
                }
            }

            @Test
            @DisplayName("요청 받은 클라이언트 권한 부여 방식의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientGrantTypeAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(grantTypeRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.GRANT_TYPES, clientCaptor.getValue().getGrantTypes());
            }

            @Nested
            @DisplayName("요청 받은 스코프가 null 일시")
            class WhenRequestingScopeIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_REDIRECT_URIS, null, OAuth2ClientApplicationTestHelper.RAW_GRANT_TYPES);
                }

                @Test
                @DisplayName("클라이언트에 스코프를 저장하지 않아야 한다.")
                void shouldNotSaveScopeForClient() {
                    ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                    service.registerNewClient(request);
                    verify(repository, times(1)).save(clientCaptor.capture());
                    assertNull(clientCaptor.getValue().getScopes());
                }
            }

            @Test
            @DisplayName("요청 받은 클라이언트 스코프의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientScopesAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(scopeRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.SCOPES, clientCaptor.getValue().getScopes());
            }

            @Test
            @DisplayName("인증 받은 클라이언트 소유자의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveAuthenticatedOwnerAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verifySaveAfterValidation(ownerRule, clientCaptor);
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.OWNER, clientCaptor.getValue().getOwner());
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 URI 가 null 일시")
            class WhenRequestingRedirectUrisIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.CLIENT_NAME, null, OAuth2ClientApplicationTestHelper.RAW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_GRANT_TYPES);
                }

                @Test
                @DisplayName("클라이언트에 리다이렉트 URI를 저장하지 않아야 한다.")
                void shouldNotSaveRedirectUrisForClient() {
                    ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                    service.registerNewClient(request);
                    verify(repository, times(1)).save(clientCaptor.capture());
                    assertNull(clientCaptor.getValue().getRedirectUris());
                }
            }

            @Test
            @DisplayName("요청 받은 라디이렉트 URI 를 저장해야 한다.")
            void shouldSaveClientRedirectUris() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verify(repository, times(1)).save(clientCaptor.capture());
                Assertions.assertEquals(OAuth2ClientApplicationTestHelper.REDIRECT_URIS, clientCaptor.getValue().getRedirectUris());
            }

            private void verifySaveAfterValidation(ValidationRule<OAuth2Client> rule, ArgumentCaptor<OAuth2Client> argumentCaptor) {
                InOrder inOrder = inOrder(rule, repository);
                inOrder.verify(rule, times(1)).isValid(argumentCaptor.capture());
                inOrder.verify(repository, times(1)).save(argumentCaptor.capture());
                assertEquals(argumentCaptor.getAllValues().get(0), argumentCaptor.getAllValues().get(1));
            }

            @AfterEach
            void after() {
                SecurityContextHolder.clearContext();
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 수정")
    class ModifyClient {

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenModifyClientNotRegisteredInRepository extends ClientNotFoundSetup {

            @Test
            @DisplayName("ClientNotFoundException 이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                OAuth2ClientModifyRequest modifyRequest = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                        OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);

                assertThrows(ClientNotFoundException.class, () -> service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest));
            }
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있을시")
        class WhenModifyClientRegisteredInRepository {

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser extends DifferentOwnerSetup {

                @Test
                @DisplayName("ClientAuthorizationException 이 발생해야 하며 에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    OAuth2ClientModifyRequest modifyRequest = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                            OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);

                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 같을시")
            class WhenMatchesClientOwnerAndAuthenticatedUser extends SameOwnerSetup {
                private OAuth2ClientModifyRequest modifyRequest;
                private OAuth2ClientValidatePolicy policy;

                @BeforeEach
                void setupConfig() {
                    this.modifyRequest = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                            OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    this.policy = OAuth2ClientApplicationTestHelper.mockValidationPolicy().build();
                    this.service.setValidatePolicy(policy);
                }

                @Test
                @DisplayName("클라이언트명을 요청한 이름으로 변경한 후 유효성 검사를 해야 한다.")
                void shouldModifyClientNameToRequestingClientName() {
                    InOrder inOrder = inOrder(client);

                    service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest);
                    inOrder.verify(client, times(1)).setClientName(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME);
                    inOrder.verify(client, times(1)).validate(policy);
                }

                @Nested
                @DisplayName("삭제할 리다이렉트 URI 가 null 일시")
                class WhenRequestingRemoveRedirectUrisIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, null,
                                OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    }

                    @Test
                    @DisplayName("클라이언트의 리다이렉트 URI 를 삭제하지 않아야 한다.")
                    void shouldNotRemoveClientsRedirectUri() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).removeRedirectUri(any());
                    }
                }

                @Nested
                @DisplayName("추가할 리다이렉트 URI 가 null 일시")
                class WhenRequestingNewRedirectUrisIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, null, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                                OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    }

                    @Test
                    @DisplayName("클라이언트의 리다이렉트 URI를 추가하지 않아야 한다.")
                    void shouldNotAddClientsRedirectUri() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).addRedirectUri(any());
                    }
                }

                @Nested
                @DisplayName("삭제할 권한 부여 방식이 null 일시")
                class WhenRequestingRemoveGrantTypeIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                                OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, null, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    }

                    @Test
                    @DisplayName("클라이언트의 권한 부여 방식을 삭제하지 않아야 한다.")
                    void shouldNotRemoveClientsGrantType() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).removeGrantType(any());
                    }
                }

                @Nested
                @DisplayName("추가할 권한 부여 방식이 null 일시")
                class WhenRequestingNewGrantTypeIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                                null, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    }

                    @Test
                    @DisplayName("클라이언트의 권한 부여 방식을 추가하지 않아야 한다.")
                    void shouldNotAddClientsGrantType() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).addGrantType(any());
                    }
                }

                @Nested
                @DisplayName("삭제할 스코프가 null 일시")
                class WhenRequestingScopeIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                                OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_NEW_SCOPES, null);
                    }

                    @Test
                    @DisplayName("클라이언트의 스코프를 삭제하지 않아야 한다.")
                    void shouldNotRemoveClientsScope() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).removeScope(any());
                    }
                }

                @Nested
                @DisplayName("추가할 스코프가 null 일시")
                class WhenRequestingNewScopeIsNull {
                    private OAuth2ClientModifyRequest request;

                    @BeforeEach
                    void setup() {
                        this.request = new OAuth2ClientModifyRequest(OAuth2ClientApplicationTestHelper.MODIFY_CLIENT_NAME, OAuth2ClientApplicationTestHelper.RAW_NEW_REDIRECT_URIS, OAuth2ClientApplicationTestHelper.RAW_REMOVE_REDIRECT_URIS,
                                OAuth2ClientApplicationTestHelper.RAW_NEW_GRANT_TYPES, OAuth2ClientApplicationTestHelper.RAW_REMOVE_GRANT_TYPES, null, OAuth2ClientApplicationTestHelper.RAW_REMOVE_SCOPES);
                    }

                    @Test
                    @DisplayName("클라이언트의 스코프를 추가하지 않아야 한다.")
                    void shouldNotAddClientsScope() {
                        service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, request);
                        verify(client, never()).addScope(any());
                    }
                }

                @Test
                @DisplayName("삭제할 리다이렉트 URI를 삭제하고 새 리다이렉트 URI 를 저장해야 한다.")
                void shouldRemoveRequestingRedirectUrisAndAddRequestingNewRedirectUris() {
                    InOrder inOrder = inOrder(client);

                    service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest);
                    OAuth2ClientApplicationTestHelper.REMOVE_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).removeRedirectUri(uri));
                    OAuth2ClientApplicationTestHelper.NEW_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).addRedirectUri(uri));
                }

                @Test
                @DisplayName("삭제할 권한 부여 방식을 삭제하고 새 권한 부여 방식을 저장한 후 유효성을 검사 해야 한다.")
                void shouldValidationClientAfterRemoveRequestingGrantTypeAndAddRequestingGrant() {
                    InOrder inOrder = inOrder(client);

                    service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest);
                    OAuth2ClientApplicationTestHelper.REMOVE_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).removeGrantType(grant));
                    OAuth2ClientApplicationTestHelper.NEW_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).addGrantType(grant));
                    inOrder.verify(client, times(1)).validate(policy);
                }

                @Test
                @DisplayName("삭제할 스코프를 삭제하고 새 스코프를 저장 한 후 유효성을 검사 해야 한다.")
                void shouldValidationClientAfterRemoveRequestingScopeAndAddRequestingNewScope() {
                    InOrder inOrder = inOrder(client);

                    service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest);
                    OAuth2ClientApplicationTestHelper.REMOVE_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).removeScope(scope));
                    OAuth2ClientApplicationTestHelper.NEW_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).addScope(scope));
                    inOrder.verify(client, times(1)).validate(policy);
                }

                @Test
                @DisplayName("클라이언트 유효성 검사 후 저장소에 저장해야 한다.")
                void shouldSaveModifiedClientAfterValidation() {
                    InOrder inOrder = inOrder(client, repository);

                    service.modifyClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, modifyRequest);
                    inOrder.verify(client, times(1)).validate(policy);
                    inOrder.verify(repository, times(1)).save(client);
                }
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 패스워드 변경")
    class ChangeClientSecret {

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenModifyClientNotRegisteredInRepository extends ClientNotFoundSetup {

            @Test
            @DisplayName("ClientNotFoundException 이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                OAuth2ChangeSecretRequest changeRequest = new OAuth2ChangeSecretRequest(OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.MODIFY_SECRET);

                assertThrows(ClientNotFoundException.class, () -> service.changeSecret(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, changeRequest));
            }
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록되어 있을시")
        class WhenModifyClientRegisteredInRepository {

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser extends DifferentOwnerSetup {

                @Test
                @DisplayName("ClientAuthorizationException 이 발생해야 하며 에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    OAuth2ChangeSecretRequest changeRequest = new OAuth2ChangeSecretRequest(OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.MODIFY_SECRET);

                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.changeSecret(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, changeRequest));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 같을시")
            class WhenSameClientOwnerAndAuthenticatedUser extends SameOwnerSetup {
                private OAuth2ChangeSecretRequest changeRequest;
                private PasswordEncoder passwordEncoder;
                private OAuth2ClientValidatePolicy policy;

                @BeforeEach
                void setupConfig() {
                    this.changeRequest = new OAuth2ChangeSecretRequest(OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.MODIFY_SECRET);
                    this.passwordEncoder = OAuth2ClientApplicationTestHelper.mockPasswordEncoder().build();
                    this.policy = OAuth2ClientApplicationTestHelper.mockValidationPolicy().build();
                    this.service.setValidatePolicy(policy);
                    this.service.setPasswordEncoder(passwordEncoder);
                }

                @Test
                @DisplayName("클라이언트 패스워드를 요청 받은 패스워드로 변경 한 후 유효성 검사를 해야 한다.")
                void shouldChangeClientSecretToRequestingSecret() {
                    InOrder inOrder = inOrder(client);

                    service.changeSecret(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, changeRequest);
                    inOrder.verify(client, times(1)).changeSecret(OAuth2ClientApplicationTestHelper.SECRET, OAuth2ClientApplicationTestHelper.MODIFY_SECRET, passwordEncoder);
                    inOrder.verify(client, times(1)).validate(policy);
                }

                @Test
                @DisplayName("패스워드의 유효성 검사 후 암호화 해야 한다.")
                void shouldEncryptedSecretAfterValidation() {
                    InOrder inOrder = inOrder(client);

                    service.changeSecret(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, changeRequest);
                    inOrder.verify(client, times(1)).validate(policy);
                    inOrder.verify(client, times(1)).encrypted(passwordEncoder);
                }

                @Test
                @DisplayName("패스워드를 암호화 한 후 저장소에 저장해야 한다.")
                void shouldSaveClientInRepositoryAfterEncrypted() {
                    InOrder inOrder = inOrder(client, repository);

                    service.changeSecret(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID, changeRequest);
                    inOrder.verify(client, times(1)).encrypted(passwordEncoder);
                    inOrder.verify(repository, times(1)).save(client);
                }
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 삭제")
    class RemoveClient {

        @Nested
        @DisplayName("삭제 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenRemoveClientNotRegisteredInRepository extends ClientNotFoundSetup {

            @Test
            @DisplayName("ClientNotFoundException 이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(ClientNotFoundException.class, () -> service.removeClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID));
            }
        }

        @Nested
        @DisplayName("삭제 하려는 클라이언트가 저장소에 등록 되어 있을시")
        class WhenRemoveClientRegisteredInRepository {

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser extends DifferentOwnerSetup {

                @Test
                @DisplayName("ClientAuthorizationException 이 발생해야 하며 에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.removeClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Nested
            @DisplayName("클라이언트의 소유자가 인증 받은 소유자와 같을시")
            class WhenSameClientOwnerAndAuthenticatedUser extends SameOwnerSetup {

                @Test
                @DisplayName("검색된 클라이언트를 저장소에서 삭제 해야 한다.")
                void shouldRemoveSearchedClient() {
                    service.removeClient(OAuth2ClientApplicationTestHelper.RAW_CLIENT_ID);

                    verify(repository, times(1)).delete(client);
                }
            }
        }
    }

    private static abstract class ClientNotFoundSetup {
        protected DefaultOAuth2ClientManagementService service;

        @BeforeEach
        void setup() {
            this.service = new DefaultOAuth2ClientManagementService(OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository().emptyClient().build());
        }
    }

    private static abstract class DifferentOwnerSetup {
        protected DefaultOAuth2ClientManagementService service;

        @BeforeEach
        void setup() {
            OAuth2Client client = OAuth2ClientApplicationTestHelper.mockOAuth2Client().configDefault().build();
            this.service = new DefaultOAuth2ClientManagementService(OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository().registerClient(client).build());
            SecurityContextHolder.getContext().setAuthentication(OAuth2ClientApplicationTestHelper.mockDifferentAuthentication());
        }

        @AfterEach
        void after() {
            SecurityContextHolder.clearContext();
        }
    }

    private static abstract class SameOwnerSetup {
        protected OAuth2ClientRepository repository;
        protected OAuth2Client client;
        protected DefaultOAuth2ClientManagementService service;

        @BeforeEach
        void setup() {
            this.client = OAuth2ClientApplicationTestHelper.mockOAuth2Client().configDefault().build();
            this.repository = OAuth2ClientApplicationTestHelper.mockOAuth2ClientRepository().registerClient(client).build();
            this.service = new DefaultOAuth2ClientManagementService(repository);

            SecurityContextHolder.getContext().setAuthentication(OAuth2ClientApplicationTestHelper.mockAuthentication());
        }

        @AfterEach
        void after() {
            SecurityContextHolder.clearContext();
        }
    }
}