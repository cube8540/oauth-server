package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.UnitTestValidationException
import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.oauth.authentication.oauth.client.domain.*
import cube8540.oauth.authentication.oauth.extractGrantType
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.*
import java.net.URI
import java.time.Duration
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType

class DefaultOAuth2ClientManagementServiceTest {

    private val repository: OAuth2ClientRepository = mockk()
    private val passwordEncoder: PasswordEncoder = mockk()
    private val validatorFactory: OAuth2ClientValidatorFactory = mockk()

    private val service = DefaultOAuth2ClientManagementService(repository)

    init {
        service.validateFactory = validatorFactory
        service.passwordEncoder = passwordEncoder
    }

    @Nested
    inner class ClientRegisterTest {

        @Test
        fun `client already registered`() {
            val registerRequest = OAuth2ClientRegisterRequest(clientId = "clientId", secret = "clientSecret", clientName = "clientName",
                redirectUris = emptyList(), scopes = emptyList(), grantTypes = emptyList(),
                accessTokenValiditySeconds = 0, refreshTokenValiditySeconds = 0, clientOwner = "owner")

            every { repository.countByClientId(OAuth2ClientId("clientId")) } returns 1

            val thrown = catchThrowable { service.registerNewClient(registerRequest) }
            assertThat(thrown).isInstanceOf(ClientRegisterException::class.java)
            assertThat((thrown as ClientRegisterException).code).isEqualTo(ErrorCodes.EXISTS_IDENTIFIER)
        }

        @Test
        fun `register client data invalid`() {
            val registerRequest = OAuth2ClientRegisterRequest(clientId = "clientId", secret = "clientSecret", clientName = "clientName",
                redirectUris = emptyList(), scopes = emptyList(), grantTypes = emptyList(),
                accessTokenValiditySeconds = 0, refreshTokenValiditySeconds = 0, clientOwner = "owner")

            every { repository.countByClientId(OAuth2ClientId("clientId")) } returns 0
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } throws UnitTestValidationException()
                }
            }

            val thrown = catchThrowable { service.registerNewClient(registerRequest) }
            assertThat(thrown).isInstanceOf(UnitTestValidationException::class.java)
        }

        @Test
        fun `register new client`() {
            val requestRedirectUri = listOf("http://locahost/1", "http://locahost/2", "http://locahost/2")
            val requestScopes = listOf("scope-1", "scope-2", "scope-3")
            val requestGrant = listOf("authorization_code", "password", "client_credentials")
            val registerRequest = OAuth2ClientRegisterRequest(clientId = "clientId", secret = "clientSecret", clientName = "clientName",
                redirectUris = requestRedirectUri, scopes = requestScopes, grantTypes = requestGrant,
                accessTokenValiditySeconds = 10, refreshTokenValiditySeconds = 20, clientOwner = "owner")

            val clientCaptor = slot<OAuth2Client>()

            every { repository.countByClientId(OAuth2ClientId("clientId")) } returns 0
            every { repository.save(capture(clientCaptor)) } returnsArgument 0
            every { passwordEncoder.encode("clientSecret") } returns "encodedClientSecret"
            every { validatorFactory.createValidator(any()) } returns mockk {
                every { result } returns mockk {
                    every { hasErrorThrows(any()) } just Runs
                }
            }

            val expectedRedirectUrl = setOf(URI.create("http://locahost/1"), URI.create("http://locahost/2"), URI.create("http://locahost/2"))
            val expectedScope = setOf(AuthorityCode("scope-1"), AuthorityCode("scope-2"), AuthorityCode("scope-3"))
            val expectedGrantType = setOf(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.PASSWORD, AuthorizationGrantType.CLIENT_CREDENTIALS)
            service.registerNewClient(registerRequest)
            assertThat(clientCaptor.captured.clientId).isEqualTo(OAuth2ClientId("clientId"))
            assertThat(clientCaptor.captured.secret).isEqualTo("encodedClientSecret")
            assertThat(clientCaptor.captured.clientName).isEqualTo("clientName")
            assertThat(clientCaptor.captured.redirectUris).isEqualTo(expectedRedirectUrl)
            assertThat(clientCaptor.captured.scopes).isEqualTo(expectedScope)
            assertThat(clientCaptor.captured.grantTypes).isEqualTo(expectedGrantType)
            assertThat(clientCaptor.captured.accessTokenValidity).isEqualTo(Duration.ofSeconds(10))
            assertThat(clientCaptor.captured.refreshTokenValidity).isEqualTo(Duration.ofSeconds(20))
        }
    }

    @Nested
    inner class ClientModifyTest {

        @Test
        fun `client not registered in repository`() {
            val modifyRequest = OAuth2ClientModifyRequest(clientName = "modifyName",
                newRedirectUris = emptyList(), removeRedirectUris = emptyList(),
                newGrantTypes = emptyList(), removeGrantTypes = emptyList(),
                newScopes = emptyList(), removeScopes = emptyList(),
                accessTokenValiditySeconds = 0, refreshTokenValiditySeconds = 0
            )

            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.empty()

            val thrown = catchThrowable { service.modifyClient("clientId", modifyRequest) }
            assertThat(thrown).isInstanceOf(ClientNotFoundException::class.java)
        }

        @Test
        fun `modify client`() {
            val newRedirectUris = listOf("http://localhost/new1", "http://localhost/new2", "http://localhost/new3")
            val removeRedirectUris = listOf("http://localhost/remove1", "http://localhost/remove2", "http://localhost/remove3")
            val newGrantType = listOf("authorization_code", "client_credentials")
            val removeGrantType = listOf("password")
            val newScope = listOf("new-scope-1", "new-scope-2", "new-scope-3")
            val removeScope = listOf("remove-scope-1", "remove-scope-2", "remove-scope-3")
            val modifyRequest = OAuth2ClientModifyRequest(clientName = "modifyName",
                newRedirectUris = newRedirectUris, removeRedirectUris = removeRedirectUris,
                newGrantTypes = newGrantType, removeGrantTypes = removeGrantType,
                newScopes = newScope, removeScopes = removeScope,
                accessTokenValiditySeconds = 10, refreshTokenValiditySeconds = 20)
            val client: OAuth2Client = mockk(relaxed = true)

            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.of(client)
            every { repository.save(client) } returnsArgument 0

            service.modifyClient("clientId", modifyRequest)
            verifyOrder {
                client.clientName = "modifyName"
                removeRedirectUris.forEach { client.removeRedirectUri(URI.create(it)) }
                newRedirectUris.forEach { client.addRedirectUri(URI.create(it)) }

                removeGrantType.forEach { client.removeGrantType(extractGrantType(it)) }
                newGrantType.forEach { client.addGrantType(extractGrantType(it)) }

                removeScope.forEach { client.removeScope(AuthorityCode(it)) }
                newScope.forEach { client.addScope(AuthorityCode(it)) }

                client.setAccessTokenValidity(10)
                client.setRefreshTokenValidity(20)

                client.validate(validatorFactory)
                repository.save(client)
            }
        }
    }

    @Nested
    inner class ModifySecretTest {

        @Test
        fun `client not registered in repository`() {
            val changeRequest = OAuth2ChangeSecretRequest("secret", "newSecret")

            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.empty()

            val thrown = catchThrowable { service.changeSecret("clientId", changeRequest) }
            assertThat(thrown).isInstanceOf(ClientNotFoundException::class.java)
        }

        @Test
        fun `change client secret`() {
            val client: OAuth2Client = mockk(relaxed = true)
            val changeRequest = OAuth2ChangeSecretRequest("secret", "newSecret")

            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.of(client)
            every { repository.save(client) } returnsArgument 0

            service.changeSecret("clientId", changeRequest)
            verifyOrder {
                client.changeSecret("secret", "newSecret", passwordEncoder)
                client.validate(validatorFactory)
                client.encrypted(passwordEncoder)
                repository.save(client)
            }
        }
    }

    @Nested
    inner class RemoveTest {

        @Test
        fun `client not registered in repository`() {
            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.empty()

            val thrown = catchThrowable { service.removeClient("clientId") }
            assertThat(thrown).isInstanceOf(ClientNotFoundException::class.java)
        }

        @Test
        fun `remove client`() {
            val client: OAuth2Client = mockk(relaxed = true)

            every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.of(client)
            every { repository.delete(client) } returnsArgument 0

            service.removeClient("clientId")
            verify { repository.delete(client) }
        }
    }

    @AfterEach
    fun clear() {
        clearAllMocks()
    }
}