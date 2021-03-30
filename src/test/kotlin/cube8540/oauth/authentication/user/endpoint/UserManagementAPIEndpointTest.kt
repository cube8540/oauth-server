package cube8540.oauth.authentication.user.endpoint

import cube8540.oauth.authentication.users.application.UserManagementService
import cube8540.oauth.authentication.users.application.UserProfile
import cube8540.oauth.authentication.users.application.UserRegisterRequest
import cube8540.oauth.authentication.users.endpoint.UserManagementAPIEndpoint
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import kotlin.random.Random

class UserManagementAPIEndpointTest {

    private val service: UserManagementService = mockk(relaxed = true)
    private val endpoint = UserManagementAPIEndpoint(service)

    @Test
    fun `counting username`() {
        val count = Random.nextLong(0, 100)

        every { service.countUser("username") } returns count

        val result = endpoint.countAccountUsername("username")
        assertThat(result["count"]).isEqualTo(count)
    }

    @Test
    fun `lookup user profile`() {
        val userProfile: UserProfile = mockk()

        every { service.loadUserProfile("username") } returns userProfile

        val result = endpoint.getProfile("username")
        assertThat(result).isEqualTo(userProfile)
    }

    @Test
    fun `remove user`() {
        endpoint.removeProfile("username")

        verify { service.removeUser("username") }
    }

    @Test
    fun `register new user`() {
        val request = UserRegisterRequest("username", "password")

        endpoint.registerUserAccount(request)
        verify { service.registerUser(request) }
    }

}