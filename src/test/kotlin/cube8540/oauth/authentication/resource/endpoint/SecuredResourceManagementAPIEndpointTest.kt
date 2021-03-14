package cube8540.oauth.authentication.resource.endpoint

import cube8540.oauth.authentication.resource.application.SecuredResourceDetails
import cube8540.oauth.authentication.resource.application.SecuredResourceManagementService
import cube8540.oauth.authentication.resource.application.SecuredResourceModifyRequest
import cube8540.oauth.authentication.resource.application.SecuredResourceRegisterRequest
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import kotlin.random.Random

class SecuredResourceManagementAPIEndpointTest {

    private val service: SecuredResourceManagementService = mockk()

    private val endpoint = SecuredResourceManagementAPIEndpoint(service)

    @Test
    fun `counting resource id`() {
        val randomCount = Random.nextLong(0, 100)

        every { service.count("resourceId") } returns randomCount

        val result = endpoint.countResourceId("resourceId")
        assertThat(result["count"]).isEqualTo(randomCount)
    }

    @Test
    fun `lookup secured resources`() {
        val resources: List<SecuredResourceDetails> = mockk()

        every { service.getResources() } returns resources

        val result = endpoint.getResources()
        assertThat(result["resources"]).isEqualTo(resources)
    }

    @Test
    fun `register new resource`() {
        val request: SecuredResourceRegisterRequest = mockk()
        val details: SecuredResourceDetails = mockk()

        every { service.registerNewResource(request) } returns details

        val result = endpoint.registerNewResource(request)
        assertThat(result).isEqualTo(details)
        verify { service.registerNewResource(request) }
    }

    @Test
    fun `modify resource`() {
        val request: SecuredResourceModifyRequest = mockk()
        val details: SecuredResourceDetails = mockk()

        every { service.modifyResource("resourceId", request) } returns details

        val result = endpoint.modifyResource("resourceId", request)
        assertThat(result).isEqualTo(details)
        verify { service.modifyResource("resourceId", request) }
    }

    @Test
    fun `remove resource`() {
        val details: SecuredResourceDetails = mockk()

        every { service.removeResource("resourceId") } returns details

        val result = endpoint.removeResource("resourceId")
        assertThat(result).isEqualTo(details)
    }
}