package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.oauth.client.domain.ClientOwner
import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.security.AuthorityDetailsService
import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.core.env.Environment
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.net.URI
import java.util.Optional

class OAuth2ClientInitializerTest {

    private val repository: OAuth2ClientRepository = mockk {
        every { save(any()) } returnsArgument 0
    }
    private val encoder: PasswordEncoder = mockk()
    private val authorityDetailsService: AuthorityDetailsService = mockk()

    private val initializer = OAuth2ClientInitializer(repository, encoder,  authorityDetailsService)

    @Test
    fun `initialize client is exists`() {
        val environment: Environment = mockk {
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_ID_KEY) } returns "clientId"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_SECRET_KEY) } returns "clientSecret"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_GRANT_TYPE_KEY) } returns "client_credentials,authorization_code,password"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_REDIRECT_URI) } returns "http://localhost:8080/auth,http://localhost:8081"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_NAME) } returns "clientName"
            every { getRequiredProperty(OAuth2ClientInitializer.USERNAME_KEY) } returns "username"
        }
        val client: OAuth2Client = mockk()

        every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.of(client)

        initializer.initialize(environment)
        verify { repository.save(any()) wasNot Called }
    }

    @Test
    fun `initialize client is not exists`() {
        val environment: Environment = mockk {
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_ID_KEY) } returns "clientId"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_SECRET_KEY) } returns "clientSecret"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_GRANT_TYPE_KEY) } returns "client_credentials,authorization_code,password"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_REDIRECT_URI) } returns "http://localhost:8080/auth,http://localhost:8081"
            every { getRequiredProperty(OAuth2ClientInitializer.CLIENT_NAME) } returns "clientName"
            every { getRequiredProperty(OAuth2ClientInitializer.USERNAME_KEY) } returns "username"
        }
        val initializeAuthorities: Set<AuthorityDetails> = setOf(
            mockk { every { code } returns "init-code-1" },
            mockk { every { code } returns "init-code-2" },
            mockk { every { code } returns "init-code-3" }
        )

        val clientCaptor = slot<OAuth2Client>()

        every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.empty()
        every { encoder.encode("clientSecret") } returns "encodedClientSecret"
        every { authorityDetailsService.loadInitializeAuthority() } returns initializeAuthorities
        every { repository.save(capture(clientCaptor)) } returnsArgument 0

        initializer.initialize(environment)
        assertThat(clientCaptor.captured.clientId).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(clientCaptor.captured.secret).isEqualTo("encodedClientSecret")
        assertThat(clientCaptor.captured.clientName).isEqualTo("clientName")
        assertThat(clientCaptor.captured.grantTypes).isEqualTo(setOf(AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.PASSWORD))
        assertThat(clientCaptor.captured.scopes).isEqualTo(setOf(AuthorityCode("init-code-1"), AuthorityCode("init-code-2"), AuthorityCode("init-code-3")))
        assertThat(clientCaptor.captured.redirectUris).isEqualTo(setOf(URI.create("http://localhost:8080/auth"), URI.create("http://localhost:8081")))
        assertThat(clientCaptor.captured.owner).isEqualTo(ClientOwner("username"))
    }

    @AfterEach
    fun clear() {
        clearAllMocks()
    }
}