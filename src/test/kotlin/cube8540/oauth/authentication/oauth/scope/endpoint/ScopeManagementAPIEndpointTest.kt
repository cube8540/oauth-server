package cube8540.oauth.authentication.oauth.scope.endpoint

import cube8540.oauth.authentication.oauth.scope.application.*
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import kotlin.random.Random

class ScopeManagementAPIEndpointTest {

    private val scopeDetailsService: OAuth2ScopeDetailsService = mockk()
    private val managementService: OAuth2ScopeManagementService = mockk()

    private val endpoint = ScopeManagementAPIEndpoint(scopeDetailsService, managementService)

    @Test
    fun `lookup registered scopes`() {
        val scopes: List<OAuth2ScopeDetails> = mockk()

        every { scopeDetailsService.loadScopes() } returns scopes

        val result = endpoint.scopes()
        assertThat(result["scopes"]).isEqualTo(scopes)
    }

    @Test
    fun `register new scope`() {
        val details: OAuth2ScopeDetails = mockk()
        val registerRequest = OAuth2ScopeRegisterRequest("scopeId", "desc")

        every { managementService.registerNewScope(registerRequest) } returns details

        val result = endpoint.registerNewScope(registerRequest)
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `modify scope`() {
        val details: OAuth2ScopeDetails = mockk()
        val modifyRequest = OAuth2ScopeModifyRequest("desc")

        every { managementService.modifyScope("scopeId", modifyRequest) } returns details

        val result = endpoint.modifyScope("scopeId", modifyRequest)
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `remove scope`() {
        val details: OAuth2ScopeDetails = mockk()

        every { managementService.removeScope("scopeId") } returns details

        val result = endpoint.removeScope("scopeId")
        assertThat(result).isEqualTo(details)
    }

    @Test
    fun `counting scope`() {
        val randomCount = Random.nextLong()

        every { managementService.countByScopeId("scopeId") } returns randomCount

        val result = endpoint.countScopeId("scopeId")
        assertThat(result["count"]).isEqualTo(randomCount)
    }

}