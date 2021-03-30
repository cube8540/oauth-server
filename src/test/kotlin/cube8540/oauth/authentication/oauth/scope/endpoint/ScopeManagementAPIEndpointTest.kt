package cube8540.oauth.authentication.oauth.scope.endpoint

import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeManagementService
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeModifyRequest
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeRegisterRequest
import cube8540.oauth.authentication.security.AuthorityDetails
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import kotlin.random.Random

class ScopeManagementAPIEndpointTest {

    private val service: OAuth2ScopeManagementService = mockk()

    private val endpoint = ScopeManagementAPIEndpoint(service)

    @Test
    fun `lookup registered scopes`() {
        val scopes: List<AuthorityDetails> = mockk()

        every { service.loadScopes() } returns scopes

        val result = endpoint.scopes()
        assertThat(result["scopes"]).isEqualTo(scopes)
    }

    @Test
    fun `register new scope`() {
        val details: AuthorityDetails = mockk()
        val registerRequest = OAuth2ScopeRegisterRequest("scopeId", "desc")

        every { service.registerNewScope(registerRequest) } returns details

        val result = endpoint.registerNewScope(registerRequest)
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `modify scope`() {
        val details: AuthorityDetails = mockk()
        val modifyRequest = OAuth2ScopeModifyRequest("desc")

        every { service.modifyScope("scopeId", modifyRequest) } returns details

        val result = endpoint.modifyScope("scopeId", modifyRequest)
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `remove scope`() {
        val details: AuthorityDetails = mockk()

        every { service.removeScope("scopeId") } returns details

        val result = endpoint.removeScope("scopeId")
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `counting scope`() {
        val randomCount = Random.nextLong()

        every { service.countByScopeId("scopeId") } returns randomCount

        val result = endpoint.countScopeId("scopeId")
        assertThat(result["count"]).isEqualTo(randomCount)
    }

}