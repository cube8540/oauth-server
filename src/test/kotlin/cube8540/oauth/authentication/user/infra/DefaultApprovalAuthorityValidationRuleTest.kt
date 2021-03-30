package cube8540.oauth.authentication.user.infra

import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.users.domain.ApprovalAuthority
import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.infra.DefaultApprovalAuthorityValidationRule
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DefaultApprovalAuthorityValidationRuleTest {

    private val clientDetailsService: OAuth2ClientDetailsService = mockk()
    private val user: User = mockk()
    private val rule: DefaultApprovalAuthorityValidationRule = DefaultApprovalAuthorityValidationRule()

    @Test
    fun `client details service is null`() {
        rule.clientDetailsService = null

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `approval authority is null`() {
        rule.clientDetailsService =  clientDetailsService

        every { user.approvalAuthorities } returns null

        assertThat(rule.isValid(user)).isTrue
    }

    @Test
    fun `approval authority is empty`() {
        rule.clientDetailsService = clientDetailsService

        every { user.approvalAuthorities } returns emptySet<ApprovalAuthority>().toMutableSet()

        assertThat(rule.isValid(user)).isTrue
    }

    @Test
    fun `client not found`() {
        rule.clientDetailsService = clientDetailsService
        every { clientDetailsService.loadClientDetailsByClientId("CLIENT-1") } throws OAuth2ClientRegistrationException("client not found")
        every { user.approvalAuthorities } returns makeApprovalScopes("CLIENT-1", setOf("TEST-1", "TEST-2", "TEST-3", "TEST-4"))

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `include scope that cannot be found`() {
        val clientDetails: OAuth2ClientDetails = mockk()

        rule.clientDetailsService = clientDetailsService
        every { clientDetails.clientId } returns "CLIENT-1"
        every { clientDetails.scopes } returns setOf("TEST-1", "TEST-2", "TEST-3")
        every { user.approvalAuthorities } returns makeApprovalScopes("CLIENT-1", setOf("TEST-1", "TEST-2", "TEST-3", "TEST-4"))
        every { clientDetailsService.loadClientDetailsByClientId("CLIENT-1") } returns clientDetails

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `allowed client scopes`() {
        val clientDetails: OAuth2ClientDetails = mockk()

        rule.clientDetailsService = clientDetailsService
        every { clientDetails.clientId } returns "CLIENT-1"
        every { clientDetails.scopes } returns setOf("TEST-1", "TEST-2", "TEST-3")
        every { user.approvalAuthorities } returns makeApprovalScopes("CLIENT-1", setOf("TEST-1", "TEST-2", "TEST-3"))
        every { clientDetailsService.loadClientDetailsByClientId("CLIENT-1") } returns clientDetails

        assertThat(rule.isValid(user)).isTrue
    }

    private fun makeApprovalScopes(clientId: String, scopes: Set<String>): MutableSet<ApprovalAuthority> =
        scopes.map { ApprovalAuthority(clientId, it) }.toMutableSet()
}