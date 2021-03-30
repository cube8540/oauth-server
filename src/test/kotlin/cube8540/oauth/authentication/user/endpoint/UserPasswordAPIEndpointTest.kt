package cube8540.oauth.authentication.user.endpoint

import cube8540.oauth.authentication.users.application.ChangePasswordRequest
import cube8540.oauth.authentication.users.application.ResetPasswordRequest
import cube8540.oauth.authentication.users.application.UserPasswordService
import cube8540.oauth.authentication.users.endpoint.UserPasswordAPIEndpoint
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test

class UserPasswordAPIEndpointTest {

    private val service: UserPasswordService = mockk(relaxed = true)
    private val endpoint = UserPasswordAPIEndpoint(service)

    @Test
    fun `change password`() {
        val changeRequest = ChangePasswordRequest("existingPassword", "newPassword")

        endpoint.changePassword("username", changeRequest)
        verify { service.changePassword("username", changeRequest) }
    }

    @Test
    fun `forgot password`() {
        endpoint.forgotPassword("username")

        verify { service.forgotPassword("username") }
    }

    @Test
    fun `reset password`() {
        val resetRequest = ResetPasswordRequest("username", "key", "newPassword")

        endpoint.resetPassword(resetRequest)
        verify { service.resetPassword(resetRequest) }
    }

}