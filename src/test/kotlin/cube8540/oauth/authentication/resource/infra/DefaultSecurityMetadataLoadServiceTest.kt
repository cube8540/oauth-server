package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.*
import cube8540.oauth.authentication.security.ScopeSecurityConfig
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.net.URI

class DefaultSecurityMetadataLoadServiceTest {

    private val repository: SecuredResourceRepository = mockk(relaxed = true)

    private val service = DefaultSecurityMetadataLoadService(repository)

    @Test
    fun `load security metadata`() {
        val authoritiesA = setOf(AccessibleAuthority("access.a.1"), AccessibleAuthority("access.a.2"))
        val authoritiesB = setOf(AccessibleAuthority("access.b.1"), AccessibleAuthority("access.b.2"))
        val authoritiesC = setOf(AccessibleAuthority("access.c.1"), AccessibleAuthority("access.c.2"))

        val resourcePOST = makeSecuredResource(URI.create("/resource"), ResourceMethod.POST, authoritiesA)
        val resourcePUT = makeSecuredResource(URI.create("/resource"), ResourceMethod.PUT, authoritiesB)
        val resourceDELETE = makeSecuredResource(URI.create("/resource"), ResourceMethod.DELETE, authoritiesC)

        every { repository.findAll() } returns listOf(resourcePOST, resourcePUT, resourceDELETE).toMutableList()

        val metadata = service.loadSecurityMetadata()
        assertThat(metadata[makeRequestMatcher(URI.create("/resource"), ResourceMethod.POST)])
            .isEqualTo(makeSecurityConfig(authoritiesA))
        assertThat(metadata[makeRequestMatcher(URI.create("/resource"), ResourceMethod.PUT)])
            .isEqualTo(makeSecurityConfig(authoritiesB))
        assertThat(metadata[makeRequestMatcher(URI.create("/resource"), ResourceMethod.DELETE)])
            .isEqualTo(makeSecurityConfig(authoritiesC))
    }

    private fun makeRequestMatcher(uri: URI, method: ResourceMethod) = when (method) {
        ResourceMethod.ALL -> AntPathRequestMatcher(uri.toString())
        else -> AntPathRequestMatcher(uri.toString(), method.toString())
    }

    private fun makeSecurityConfig(authorityCodes: Set<AccessibleAuthority>) = authorityCodes
        .map { ScopeSecurityConfig(it.authority) }
        .toSet()

    private fun makeSecuredResource(uri: URI, resourceMethod: ResourceMethod, accessible: Set<AccessibleAuthority>) =
        mockk<SecuredResource> {
            every { resource } returns uri
            every { method } returns resourceMethod
            every { authorities } returns accessible.toMutableSet()
        }
}