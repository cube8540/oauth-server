package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.SecuredResource
import cube8540.oauth.authentication.resource.domain.SecuredResourceId
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SecuredResourceIdRuleTest {

    private val resource: SecuredResource = mockk()

    private val rule = SecuredResourceIdRule()

    @Test
    fun `resource id is empty`() {
        every { resource.resourceId } returns SecuredResourceId("")

        val result = rule.isValid(resource)
        assertThat(result).isFalse
    }

    @Test
    fun `resource is not empty`() {
        every { resource.resourceId } returns SecuredResourceId("resourceId")

        val result = rule.isValid(resource)
        assertThat(result).isTrue
    }
}