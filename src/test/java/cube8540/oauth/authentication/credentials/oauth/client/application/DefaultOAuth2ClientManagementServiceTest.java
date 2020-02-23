package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientValidatePolicy;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientErrorCodes;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.client.error.ClientRegisterException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.validator.core.ValidationRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 관리 서비스 테스트")
class DefaultOAuth2ClientManagementServiceTest {

    private static final String RAW_CLIENT_ID = "CLIENT_ID";
    private static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    private static final String SECRET = "SECRET";
    private static final String ENCODING_SECRET = "ENCODING-SECRET";
    private static final String MODIFY_SECRET = "MODIFY-SECRET";
    private static final String ENCODING_MODIFY_SECRET = "ENCODING-MODIFY-SECRET";

    private static final String CLIENT_NAME = "CLIENT-NAME";
    private static final String MODIFY_CLIENT_NAME = "MODIFY-CLIENT-NAME";

    private static final Set<URI> REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080"), URI.create("http://localhost:8081"), URI.create("http://localhost:8082")));
    private static final Set<URI> NEW_REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080/new"), URI.create("http://localhost:8081/new"), URI.create("http://localhost:8082/new")));
    private static final Set<URI> REMOVE_REDIRECT_URIS = new HashSet<>(Arrays.asList(URI.create("http://localhost:8080/remove"), URI.create("http://localhost:8081/remove"), URI.create("http://localhost:8082/remove")));
    private static final List<String> RAW_REDIRECT_URIS = REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());
    private static final List<String> RAW_NEW_REDIRECT_URIS = NEW_REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());
    private static final List<String> RAW_REMOVE_REDIRECT_URIS = REMOVE_REDIRECT_URIS.stream().map(URI::toString).collect(Collectors.toList());

    private static final Set<AuthorizationGrantType> GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.PASSWORD, AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN));
    private static final Set<AuthorizationGrantType> NEW_GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.IMPLICIT, AuthorizationGrantType.CLIENT_CREDENTIALS));
    private static final Set<AuthorizationGrantType> REMOVE_GRANT_TYPES = new HashSet<>(Arrays.asList(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.PASSWORD, AuthorizationGrantType.REFRESH_TOKEN));
    private static final List<String> RAW_GRANT_TYPES = GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
    private static final List<String> RAW_NEW_GRANT_TYPES = NEW_GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());
    private static final List<String> RAW_REMOVE_GRANT_TYPES = REMOVE_GRANT_TYPES.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toList());

    private static final Set<OAuth2ScopeId> SCOPES = new HashSet<>(Arrays.asList(new OAuth2ScopeId("SCOPE-1"), new OAuth2ScopeId("SCOPE-2"), new OAuth2ScopeId("SCOPE-3")));
    private static final Set<OAuth2ScopeId> NEW_SCOPES = new HashSet<>(Arrays.asList(new OAuth2ScopeId("NEW-SCOPE-1"), new OAuth2ScopeId("NEW-SCOPE-1"), new OAuth2ScopeId("NEW-SCOPE-1")));
    private static final Set<OAuth2ScopeId> REMOVE_SCOPES = new HashSet<>(Arrays.asList(new OAuth2ScopeId("REMOVE-SCOPE-1"), new OAuth2ScopeId("REMOVE-SCOPE-2"), new OAuth2ScopeId("REMOVE-SCOPE-3")));
    private static final List<String> RAW_SCOPES = SCOPES.stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());
    private static final List<String> RAW_NEW_SCOPES = NEW_SCOPES.stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());
    private static final List<String> RAW_REMOVE_SCOPES = REMOVE_SCOPES.stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());

    private static final String RAW_OWNER = "owner@email.com";
    private static final UserEmail OWNER = new UserEmail(RAW_OWNER);

    private static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(10);
    private static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofHours(12);

    private PasswordEncoder passwordEncoder;
    private OAuth2ClientRepository repository;
    private DefaultOAuth2ClientManagementService service;

    @BeforeEach
    void setup() {
        this.passwordEncoder = mock(PasswordEncoder.class);
        this.repository = mock(OAuth2ClientRepository.class);
        this.service = new DefaultOAuth2ClientManagementService(repository);

        when(this.passwordEncoder.encode(SECRET)).thenReturn(ENCODING_SECRET);
        when(this.passwordEncoder.encode(MODIFY_SECRET)).thenReturn(ENCODING_MODIFY_SECRET);

        this.service.setPasswordEncoder(passwordEncoder);
    }

    @Nested
    @DisplayName("클라이언트 아이디 카운팅")
    class CountingClientId {
        private long randomCount;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);
            when(repository.countByClientId(CLIENT_ID)).thenReturn(randomCount);
        }

        @Test
        @DisplayName("저장소에서 요청 받은 클라이언트 아이디의 갯수를 검색하여 반환해야 한다.")
        void shouldReturnsCountClientIdInRepository() {
            long count = service.countClient(RAW_CLIENT_ID);
            assertEquals(randomCount, count);
        }
    }

    @Nested
    @DisplayName("새 클라이언트 추가")
    class RegisterNewClient {
        private OAuth2ClientRegisterRequest request;

        @BeforeEach
        void setup() {
            this.request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME, RAW_REDIRECT_URIS, RAW_SCOPES, RAW_GRANT_TYPES);
        }

        @Nested
        @DisplayName("저장소에 이미 저장된 클라이언트의 아이디일시")
        class WhenExistingClientIdInRepository {

            @BeforeEach
            void setup() {
                when(repository.countByClientId(CLIENT_ID)).thenReturn(1L);
            }

            @Test
            @DisplayName("ClientRegisterException이 발생해야 한다.")
            void shouldThrowsClientRegisterException() {
                assertThrows(ClientRegisterException.class, () -> service.registerNewClient(request));
            }

            @Test
            @DisplayName("에러 코드는 EXISTS_IDENTIFIER 이어야 한다.")
            void shouldErrorCodeIsExistsIdentifier() {
                ClientRegisterException e = assertThrows(ClientRegisterException.class, () -> service.registerNewClient(request));
                assertEquals(ClientErrorCodes.EXISTS_IDENTIFIER, e.getCode());
            }
        }

        @Nested
        @DisplayName("저장소에 없는 클라이언트 아이디일시")
        class WhenNotExistingClientIdInRepository {

            private ValidationRule<OAuth2Client> clientIdRule;
            private ValidationRule<OAuth2Client> secretRule;
            private ValidationRule<OAuth2Client> clientNameRule;
            private ValidationRule<OAuth2Client> grantTypeRule;
            private ValidationRule<OAuth2Client> scopeRule;
            private ValidationRule<OAuth2Client> ownerRule;

            @BeforeEach
            @SuppressWarnings("unchecked")
            void setup() {
                OAuth2ClientValidatePolicy policy = mock(OAuth2ClientValidatePolicy.class);
                Authentication authentication = mock(Authentication.class);

                this.clientIdRule = mock(ValidationRule.class);
                this.secretRule = mock(ValidationRule.class);
                this.clientNameRule = mock(ValidationRule.class);
                this.grantTypeRule = mock(ValidationRule.class);
                this.scopeRule = mock(ValidationRule.class);
                this.ownerRule = mock(ValidationRule.class);

                when(policy.clientIdRule()).thenReturn(clientIdRule);
                when(policy.secretRule()).thenReturn(secretRule);
                when(policy.clientNameRule()).thenReturn(clientNameRule);
                when(policy.grantTypeRule()).thenReturn(grantTypeRule);
                when(policy.scopeRule()).thenReturn(scopeRule);
                when(policy.ownerRule()).thenReturn(ownerRule);
                when(repository.countByClientId(CLIENT_ID)).thenReturn(0L);

                when(clientIdRule.isValid(any())).thenReturn(true);
                when(secretRule.isValid(any())).thenReturn(true);
                when(clientNameRule.isValid(any())).thenReturn(true);
                when(grantTypeRule.isValid(any())).thenReturn(true);
                when(scopeRule.isValid(any())).thenReturn(true);
                when(ownerRule.isValid(any())).thenReturn(true);

                doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));
                when(authentication.getName()).thenReturn(RAW_OWNER);

                service.setValidatePolicy(policy);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            @Test
            @DisplayName("요청 받은 클라이언트 아이디의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientIdAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
                InOrder inOrder = inOrder(clientIdRule, repository);

                service.registerNewClient(request);
                inOrder.verify(clientIdRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(CLIENT_ID, clientCaptor.getValue().getClientId());
            }

            @Test
            @DisplayName("요청 받은 클라이언트 패스워드의 유효성을 검사한 후 암호화 하여 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientSecretAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
                InOrder inOrder = inOrder(secretRule, repository, passwordEncoder);

                service.registerNewClient(request);
                inOrder.verify(secretRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(passwordEncoder, times(1)).encode(SECRET);
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(ENCODING_SECRET, clientCaptor.getValue().getSecret());
            }

            @Test
            @DisplayName("요청 받은 클라이언트명의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveRequestingClientNameAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
                InOrder inOrder = inOrder(clientNameRule, repository);

                service.registerNewClient(request);
                inOrder.verify(clientNameRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(CLIENT_NAME, clientCaptor.getValue().getClientName());
            }

            @Nested
            @DisplayName("요청 받은 권한 부여 방식이 null일시")
            class WhenRequestingGrantTypeIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME, RAW_REDIRECT_URIS, RAW_SCOPES, null);
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
                InOrder inOrder = inOrder(grantTypeRule, repository);

                service.registerNewClient(request);
                inOrder.verify(grantTypeRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(GRANT_TYPES, clientCaptor.getValue().getGrantTypes());
            }

            @Nested
            @DisplayName("요청 받은 스코프가 null일시")
            class WhenRequestingScopeIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME, RAW_REDIRECT_URIS, null, RAW_GRANT_TYPES);
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
                InOrder inOrder = inOrder(scopeRule, repository);

                service.registerNewClient(request);
                inOrder.verify(scopeRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(SCOPES, clientCaptor.getValue().getScopes());
            }

            @Test
            @DisplayName("인증 받은 클라이언트 소유자의 유효성을 검사한 후 저장소에 저장해야 한다.")
            void shouldSaveAuthenticatedOwnerAfterValidation() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);
                InOrder inOrder = inOrder(ownerRule, repository);

                service.registerNewClient(request);
                inOrder.verify(ownerRule, times(1)).isValid(clientCaptor.capture());
                inOrder.verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(clientCaptor.getAllValues().get(0), clientCaptor.getAllValues().get(1));
                assertEquals(OWNER, clientCaptor.getValue().getOwner());
            }

            @Nested
            @DisplayName("요청 받은 리다이렉트 URI가 null일시")
            class WhenRequestingRedirectUrisIsNull {
                private OAuth2ClientRegisterRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientRegisterRequest(RAW_CLIENT_ID, SECRET, CLIENT_NAME, null, RAW_SCOPES, RAW_GRANT_TYPES);
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
            @DisplayName("요청 받은 라디이렉트 URI를 저장해야 한다.")
            void shouldSaveClientRedirectUris() {
                ArgumentCaptor<OAuth2Client> clientCaptor = ArgumentCaptor.forClass(OAuth2Client.class);

                service.registerNewClient(request);
                verify(repository, times(1)).save(clientCaptor.capture());
                assertEquals(REDIRECT_URIS, clientCaptor.getValue().getRedirectUris());
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 수정")
    class ModifyClient {
        private OAuth2ClientModifyRequest modifyRequest;
        private OAuth2ClientValidatePolicy policy;

        @BeforeEach
        void setup() {
            this.modifyRequest = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, RAW_REMOVE_REDIRECT_URIS,
                    RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES);
            this.policy = mock(OAuth2ClientValidatePolicy.class);

            Authentication authentication = mock(Authentication.class);
            when(authentication.getName()).thenReturn(RAW_OWNER);

            doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));

            service.setValidatePolicy(policy);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenModifyClientNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("ClientNotFoundException이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(ClientNotFoundException.class, () -> service.modifyClient(RAW_CLIENT_ID, modifyRequest));
            }
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있을시")
        class WhenModifyClientRegisteredInRepository {

            private OAuth2Client client;

            @BeforeEach
            void setup() {
                OAuth2Client modifiedClient = mock(OAuth2Client.class);
                Authentication authentication = mock(Authentication.class);

                this.client = mock(OAuth2Client.class);

                when(client.getOwner()).thenReturn(OWNER);
                when(authentication.getName()).thenReturn(RAW_OWNER);
                when(modifiedClient.getClientId()).thenReturn(CLIENT_ID);
                when(modifiedClient.getClientName()).thenReturn(MODIFY_CLIENT_NAME);
                when(modifiedClient.getOwner()).thenReturn(OWNER);
                when(modifiedClient.getRedirectUris()).thenReturn(NEW_REDIRECT_URIS);
                when(modifiedClient.getScopes()).thenReturn(NEW_SCOPES);
                when(modifiedClient.getGrantTypes()).thenReturn(NEW_GRANT_TYPES);
                when(modifiedClient.getAccessTokenValidity()).thenReturn(ACCESS_TOKEN_VALIDITY);
                when(modifiedClient.getRefreshTokenValidity()).thenReturn(REFRESH_TOKEN_VALIDITY);
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
                when(repository.save(client)).thenReturn(modifiedClient);

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser {
                @BeforeEach
                void setup() {
                    when(client.getOwner()).thenReturn(new UserEmail("different@email.com"));
                }

                @Test
                @DisplayName("ClientAuthorizationException이 발생해야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    assertThrows(ClientAuthorizationException.class, () -> service.modifyClient(RAW_CLIENT_ID, modifyRequest));
                }

                @Test
                @DisplayName("에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldErrorCodeIsInvalidOwner() {
                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.modifyClient(RAW_CLIENT_ID, modifyRequest));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Test
            @DisplayName("클라이언트명을 요청한 이름으로 변경한 후 유효성 검사를 해야 한다.")
            void shouldModifyClientNameToRequestingClientName() {
                InOrder inOrder = inOrder(client);

                service.modifyClient(RAW_CLIENT_ID, modifyRequest);
                inOrder.verify(client, times(1)).setClientName(MODIFY_CLIENT_NAME);
                inOrder.verify(client, times(1)).validate(policy);
            }

            @Nested
            @DisplayName("삭제할 리다이렉트 URI가 null일시")
            class WhenRequestingRemoveRedirectUrisIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, null,
                            RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES);
                }

                @Test
                @DisplayName("클라이언트의 리다이렉트 URI를 삭제하지 않아야 한다.")
                void shouldNotRemoveClientsRedirectUri() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).removeRedirectUri(any());
                }
            }

            @Nested
            @DisplayName("추가할 리다이렉트 URI가 null일시")
            class WhenRequestingNewRedirectUrisIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, null, RAW_REMOVE_REDIRECT_URIS,
                            RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES);
                }

                @Test
                @DisplayName("클라이언트의 리다이렉트 URI를 추가하지 않아야 한다.")
                void shouldNotAddClientsRedirectUri() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).addRedirectUri(any());
                }
            }

            @Nested
            @DisplayName("삭제할 권한 부여 방식이 null일시")
            class WhenRequestingRemoveGrantTypeIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, RAW_REMOVE_REDIRECT_URIS,
                            RAW_NEW_GRANT_TYPES, null, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES);
                }

                @Test
                @DisplayName("클라이언트의 권한 부여 방식을 삭제하지 않아야 한다.")
                void shouldNotRemoveClientsGrantType() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).removeGrantType(any());
                }
            }

            @Nested
            @DisplayName("추가할 권한 부여 방식이 null일시")
            class WhenRequestingNewGrantTypeIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, RAW_REMOVE_REDIRECT_URIS,
                            null, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, RAW_REMOVE_SCOPES);
                }

                @Test
                @DisplayName("클라이언트의 권한 부여 방식을 추가하지 않아야 한다.")
                void shouldNotAddClientsGrantType() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).addGrantType(any());
                }
            }

            @Nested
            @DisplayName("삭제할 스코프가 null일시")
            class WhenRequestingScopeIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, RAW_REMOVE_REDIRECT_URIS,
                            RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, RAW_NEW_SCOPES, null);
                }

                @Test
                @DisplayName("클라이언트의 스코프를 삭제하지 않아야 한다.")
                void shouldNotRemoveClientsScope() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).removeScope(any());
                }
            }

            @Nested
            @DisplayName("추가할 스코프가 null일시")
            class WhenRequestingNewScopeIsNull {
                private OAuth2ClientModifyRequest request;

                @BeforeEach
                void setup() {
                    this.request = new OAuth2ClientModifyRequest(MODIFY_CLIENT_NAME, RAW_NEW_REDIRECT_URIS, RAW_REMOVE_REDIRECT_URIS,
                            RAW_NEW_GRANT_TYPES, RAW_REMOVE_GRANT_TYPES, null, RAW_REMOVE_SCOPES);
                }

                @Test
                @DisplayName("클라이언트의 스코프를 추가하지 않아야 한다.")
                void shouldNotAddClientsScope() {
                    service.modifyClient(RAW_CLIENT_ID, request);
                    verify(client, never()).addScope(any());
                }
            }

            @Test
            @DisplayName("삭제할 리다이렉트 URI를 삭제하고 새 리다이렉트 URI를 저장해야 한다.")
            void shouldRemoveRequestingRedirectUrisAndAddRequestingNewRedirectUris() {
                InOrder inOrder = inOrder(client);

                service.modifyClient(RAW_CLIENT_ID, modifyRequest);
                REMOVE_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).removeRedirectUri(uri));
                NEW_REDIRECT_URIS.forEach(uri -> inOrder.verify(client, times(1)).addRedirectUri(uri));
            }

            @Test
            @DisplayName("삭제할 권한 부여 방식을 삭제하고 새 권한 부여 방식을 저장한 후 유효성을 검사 해야 한다.")
            void shouldValidationClientAfterRemoveRequestingGrantTypeAndAddRequestingGrant() {
                InOrder inOrder = inOrder(client);

                service.modifyClient(RAW_CLIENT_ID, modifyRequest);
                REMOVE_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).removeGrantType(grant));
                NEW_GRANT_TYPES.forEach(grant -> inOrder.verify(client, times(1)).addGrantType(grant));
                inOrder.verify(client, times(1)).validate(policy);
            }

            @Test
            @DisplayName("삭제할 스코프를 삭제하고 새 스코프를 저장 한 후 유효성을 검사 해야 한다.")
            void shouldValidationClientAfterRemoveRequestingScopeAndAddRequestingNewScope() {
                InOrder inOrder = inOrder(client);

                service.modifyClient(RAW_CLIENT_ID, modifyRequest);
                REMOVE_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).removeScope(scope));
                NEW_SCOPES.forEach(scope -> inOrder.verify(client, times(1)).addScope(scope));
                inOrder.verify(client, times(1)).validate(policy);
            }

            @Test
            @DisplayName("클라이언트 유효성 검사 후 저장소에 저장해야 한다.")
            void shouldSaveModifiedClientAfterValidation() {
                InOrder inOrder = inOrder(client, repository);

                service.modifyClient(RAW_CLIENT_ID, modifyRequest);
                inOrder.verify(client, times(1)).validate(policy);
                inOrder.verify(repository, times(1)).save(client);
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 패스워드 변경")
    class ChangeClientSecret {
        private OAuth2Client client;
        private OAuth2ClientValidatePolicy policy;
        private OAuth2ChangeSecretRequest changeRequest;

        @BeforeEach
        void setup() {
            Authentication authentication = mock(Authentication.class);

            this.client = mock(OAuth2Client.class);
            this.policy = mock(OAuth2ClientValidatePolicy.class);
            this.changeRequest = new OAuth2ChangeSecretRequest(SECRET, MODIFY_SECRET);

            when(authentication.getName()).thenReturn(RAW_OWNER);
            when(client.getClientId()).thenReturn(CLIENT_ID);
            when(client.getClientName()).thenReturn(CLIENT_NAME);
            when(client.getOwner()).thenReturn(OWNER);
            when(client.getRedirectUris()).thenReturn(REDIRECT_URIS);
            when(client.getScopes()).thenReturn(SCOPES);
            when(client.getGrantTypes()).thenReturn(GRANT_TYPES);
            when(client.getAccessTokenValidity()).thenReturn(ACCESS_TOKEN_VALIDITY);
            when(client.getRefreshTokenValidity()).thenReturn(REFRESH_TOKEN_VALIDITY);

            doAnswer(returnsFirstArg()).when(repository).save(isA(OAuth2Client.class));

            service.setValidatePolicy(policy);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenModifyClientNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("ClientNotFoundException이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(ClientNotFoundException.class, () -> service.changeSecret(RAW_CLIENT_ID, changeRequest));
            }
        }

        @Nested
        @DisplayName("수정 하려는 클라이언트가 저장소에 등록되어 있을시")
        class WhenModifyClientRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
            }

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser {
                @BeforeEach
                void setup() {
                    when(client.getOwner()).thenReturn(new UserEmail("different@email.com"));
                }

                @Test
                @DisplayName("ClientAuthorizationException이 발생해야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    assertThrows(ClientAuthorizationException.class, () -> service.changeSecret(RAW_CLIENT_ID, changeRequest));
                }

                @Test
                @DisplayName("에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldErrorCodeIsInvalidOwner() {
                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.changeSecret(RAW_CLIENT_ID, changeRequest));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Test
            @DisplayName("클라이언트 패스워드를 요청 받은 패스워드로 변경 한 후 유효성 검사를 해야 한다.")
            void shouldChangeClientSecretToRequestingSecret() {
                InOrder inOrder = inOrder(client);

                service.changeSecret(RAW_CLIENT_ID, changeRequest);
                inOrder.verify(client, times(1)).changeSecret(SECRET, MODIFY_SECRET, passwordEncoder);
                inOrder.verify(client, times(1)).validate(policy);
            }

            @Test
            @DisplayName("패스워드의 유효성 검사 후 암호화 해야 한다.")
            void shouldEncryptedSecretAfterValidation() {
                InOrder inOrder = inOrder(client);

                service.changeSecret(RAW_CLIENT_ID, changeRequest);
                inOrder.verify(client, times(1)).validate(policy);
                inOrder.verify(client, times(1)).encrypted(passwordEncoder);
            }

            @Test
            @DisplayName("패스워드를 암호화 한 후 저장소에 저장해야 한다.")
            void shouldSaveClientInRepositoryAfterEncrypted() {
                InOrder inOrder = inOrder(client, repository);

                service.changeSecret(RAW_CLIENT_ID, changeRequest);
                inOrder.verify(client, times(1)).encrypted(passwordEncoder);
                inOrder.verify(repository, times(1)).save(client);
            }
        }
    }

    @Nested
    @DisplayName("클라이언트 삭제")
    class RemoveClient {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            Authentication authentication = mock(Authentication.class);
            this.client = mock(OAuth2Client.class);

            when(authentication.getName()).thenReturn(RAW_OWNER);
            when(client.getClientId()).thenReturn(CLIENT_ID);
            when(client.getClientName()).thenReturn(CLIENT_NAME);
            when(client.getOwner()).thenReturn(OWNER);
            when(client.getRedirectUris()).thenReturn(REDIRECT_URIS);
            when(client.getScopes()).thenReturn(SCOPES);
            when(client.getGrantTypes()).thenReturn(GRANT_TYPES);
            when(client.getAccessTokenValidity()).thenReturn(ACCESS_TOKEN_VALIDITY);
            when(client.getRefreshTokenValidity()).thenReturn(REFRESH_TOKEN_VALIDITY);

            when(authentication.getName()).thenReturn(RAW_OWNER);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        @Nested
        @DisplayName("삭제 하려는 클라이언트가 저장소에 등록 되어 있지 않을시")
        class WhenRemoveClientNotRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.empty());
            }

            @Test
            @DisplayName("ClientNotFoundException이 발생해야 한다.")
            void shouldThrowsClientNotFoundException() {
                assertThrows(ClientNotFoundException.class, () -> service.removeClient(RAW_CLIENT_ID));
            }
        }

        @Nested
        @DisplayName("삭제 하려는 클라이언트가 저장소에 등록 되어 있을시")
        class WhenRemoveClientRegisteredInRepository {

            @BeforeEach
            void setup() {
                when(repository.findByClientId(CLIENT_ID)).thenReturn(Optional.of(client));
            }

            @Nested
            @DisplayName("클라이언트의 소유자와 인증 받은 소유자가 다를시")
            class WhenDifferentClientOwnerAndAuthenticatedUser {
                @BeforeEach
                void setup() {
                    when(client.getOwner()).thenReturn(new UserEmail("different@email.com"));
                }

                @Test
                @DisplayName("ClientAuthorizationException이 발생해야 한다.")
                void shouldThrowsClientAuthorizationException() {
                    assertThrows(ClientAuthorizationException.class, () -> service.removeClient(RAW_CLIENT_ID));
                }

                @Test
                @DisplayName("에러 코드는 INVALID_OWNER 이어야 한다.")
                void shouldErrorCodesIsInvalidOwner() {
                    ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> service.removeClient(RAW_CLIENT_ID));
                    assertEquals(ClientErrorCodes.INVALID_OWNER, e.getCode());
                }
            }

            @Test
            @DisplayName("검색된 클라이언트를 저장소에서 삭제 해야 한다.")
            void shouldRemoveSearchedClient() {
                service.removeClient(RAW_CLIENT_ID);

                verify(repository, times(1)).delete(client);
            }
        }
    }
}