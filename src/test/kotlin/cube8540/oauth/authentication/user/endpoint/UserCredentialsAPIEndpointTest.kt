package cube8540.oauth.authentication.user.endpoint

import cube8540.oauth.authentication.users.application.UserCredentialsService
import cube8540.oauth.authentication.users.endpoint.UserCredentialsAPIEndpoint
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test

class UserCredentialsAPIEndpointTest {

    private val service: UserCredentialsService = mockk(relaxed = true)
    private val endpoint = UserCredentialsAPIEndpoint(service)

    @Test
    fun `account credentials`() {
        endpoint.credentials("username", "key")

        verify { service.accountCredentials("username", "key") }
    }

    @Test
    fun `grant credentials key to request account`() {
        endpoint.generateCredentialsKey("username")

        verify { service.grantCredentialsKey("username") }
    }
}