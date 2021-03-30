package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.error.UserDeniedAuthorizationException
import cube8540.oauth.authentication.oauth.security.AuthorizationRequest
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test

class DefaultScopeApprovalResolverTest {

    private val resolver = DefaultScopeApprovalResolver()

    @Test
    fun `not has approval scope`() {
        val authorizationRequest: AuthorizationRequest = mockk {
            every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
        }
        val approvalScopes: MutableMap<String, String> = HashMap()

        approvalScopes["scope-1"] = "false"
        approvalScopes["scope-2"] = "FALSE"
        approvalScopes["scope-3"] = "any"

        val thrown = catchThrowable { resolver.resolveApprovalScopes(authorizationRequest, approvalScopes) }
        assertThat(thrown).isInstanceOf(UserDeniedAuthorizationException::class.java)
    }

    @Test
    fun `extract approval scope`() {
        val authorizationRequest: AuthorizationRequest = mockk {
            every { requestScopes } returns setOf("scope-1", "scope-2", "scope-3")
        }
        val approvalScopes: MutableMap<String, String> = HashMap()

        approvalScopes["scope-1"] = "true"
        approvalScopes["scope-2"] = "TRUE"
        approvalScopes["scope-3"] = "any"

        val resolvedApprovalScopes = resolver.resolveApprovalScopes(authorizationRequest, approvalScopes)
        assertThat(resolvedApprovalScopes).isEqualTo(setOf("scope-1", "scope-2"))
    }

}