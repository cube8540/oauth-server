package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.SecuredResource
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URI

class SecuredResourceRuleTest {

    private val resource: SecuredResource = mockk()

    private val rule = SecuredResourceRule()

    @Test
    fun `resource url is empty`() {
        every { resource.resource } returns URI.create("")

        val result = rule.isValid(resource)
        assertThat(result).isFalse
    }

    @Test
    fun `resource url is not empty`() {
        every { resource.resource } returns URI.create("http://localhost")

        val result = rule.isValid(resource)
        assertThat(result).isTrue
    }
}