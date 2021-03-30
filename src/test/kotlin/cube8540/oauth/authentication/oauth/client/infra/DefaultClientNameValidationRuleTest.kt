package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DefaultClientNameValidationRuleTest {

    private val rule = DefaultClientNameValidationRule()

    @Test
    fun `client name must not be null`() {
        val client: OAuth2Client = mockk {
            every { clientName } returns null
        }

        val result = rule.isValid(client)
        assertThat(result).isFalse
    }
}