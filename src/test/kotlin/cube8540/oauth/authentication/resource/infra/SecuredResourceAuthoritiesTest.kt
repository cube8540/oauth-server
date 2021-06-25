package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.AccessibleAuthority
import cube8540.oauth.authentication.resource.domain.SecuredResource
import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.security.AuthorityDetailsService
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SecuredResourceAuthoritiesTest {

    private val resource: SecuredResource = mockk()
    private val authorityDetailsService: AuthorityDetailsService = mockk()

    private val rule = SecuredResourceAuthoritiesRule(authorityDetailsService)

    @Test
    fun `authorities is null`() {
        every { resource.authorities } returns null

        val result = rule.isValid(resource)
        assertThat(result).isTrue
    }

    @Test
    fun `authorities is empty`() {
        every { resource.authorities } returns emptySet<AccessibleAuthority>().toMutableSet()

        val result = rule.isValid(resource)
        assertThat(result).isTrue
    }

    @Test
    fun `included not found authority`() {
        val resourceAuthorities = setOf(AccessibleAuthority("access.1"), AccessibleAuthority("access.2"), AccessibleAuthority("access.3")).toMutableSet()
        val rawResourceAuthorities = resourceAuthorities.map { it.authority }.toSet()
        val storedAuthorities = listOf(TestAuthorityDetails("access.1"), TestAuthorityDetails("access.2"))

        every { resource.authorities } returns resourceAuthorities
        every { authorityDetailsService.loadAuthorityByAuthorityCodes(rawResourceAuthorities) } returns storedAuthorities

        val result = rule.isValid(resource)
        assertThat(result).isFalse
    }

    @Test
    fun `all authorities are searched`() {
        val resourceAuthorities = setOf(AccessibleAuthority("access.1"), AccessibleAuthority("access.2"), AccessibleAuthority("access.3")).toMutableSet()
        val rawResourceAuthorities = resourceAuthorities.map { it.authority }.toSet()
        val storedAuthorities = listOf(TestAuthorityDetails("access.1"), TestAuthorityDetails("access.2"), TestAuthorityDetails("access.3"))

        every { resource.authorities } returns resourceAuthorities
        every { authorityDetailsService.loadAuthorityByAuthorityCodes(rawResourceAuthorities) } returns storedAuthorities

        val result = rule.isValid(resource)
        assertThat(result).isTrue
    }

    private inner class TestAuthorityDetails(override val code: String): AuthorityDetails

}