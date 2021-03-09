package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.users.application.UserApprovalAuthorityService
import cube8540.oauth.authentication.users.application.UserAutoApprovalScopeHandler
import cube8540.oauth.authentication.users.domain.ApprovalAuthority
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.Principal

class UserAutoApprovalScopeHandlerTest {

    private val approvalService: UserApprovalAuthorityService = mockk()
    private val handler = UserAutoApprovalScopeHandler(approvalService)

    @Test
    fun `filtering required approval scope`() {
        val requestApprovalScope = setOf("TEST-1", "TEST-2", "TEST-3", "TEST-4", "TEST-5")
        val approvalScopeInClientA = listOf("TEST-1", "TEST-2", "TEST-3")
        val approvalScopeInClientB = listOf("TEST-2", "TEST-3", "TEST-4")
        val approvalScopeInClientC = listOf("TEST-3", "TEST-4", "TEST-5")
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientA"
        }
        val principal: Principal = mockk {
            every { name } returns "username"
        }
        val userApprovalScopes = approvalScopeInClientA.map { ApprovalAuthority("clientA", it) } +
                approvalScopeInClientB.map { ApprovalAuthority("clientB", it) } +
                approvalScopeInClientC.map { ApprovalAuthority("clientC", it) }

        every { approvalService.getApprovalAuthorities("username") } returns userApprovalScopes

        val results = handler.filterRequiredPermissionScopes(principal, clientDetails, requestApprovalScope)
        assertThat(results).isEqualTo(requestApprovalScope.subtract(approvalScopeInClientA))
    }

    @Test
    fun `save auto approval scope`() {
        val storeApprovalCaptor = slot<Collection<ApprovalAuthority>>()
        val requestApprovalScope = setOf("TEST-1", "TEST-2", "TEST-3")
        val principal: Principal = mockk {
            every { name } returns "username"
        }
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
        }

        every { approvalService.grantApprovalAuthorities(eq("username"), capture(storeApprovalCaptor)) } returns mockk()

        handler.storeAutoApprovalScopes(principal, clientDetails, requestApprovalScope)
        assertThat(storeApprovalCaptor.isCaptured).isTrue
        assertThat(storeApprovalCaptor.captured).isEqualTo(
            requestApprovalScope.map { ApprovalAuthority("clientId", it) }.toSet()
        )
    }
}