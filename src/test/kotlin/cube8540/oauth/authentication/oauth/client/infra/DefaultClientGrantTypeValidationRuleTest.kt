package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.AuthorizationGrantType

class DefaultClientGrantTypeValidationRuleTest {

    private val rule = DefaultClientGrantTypeValidationRule()

    @Test
    fun `client grant type must not be null`() {
        val client: OAuth2Client = mockk {
            every { grantTypes } returns null
        }

        val result = rule.isValid(client)
        assertThat(result).isFalse
    }

    @Test
    fun `client grant type must not be empty`() {
        val client: OAuth2Client = mockk {
            every { grantTypes } returns emptySet<AuthorizationGrantType>().toMutableSet()
        }

        val result = rule.isValid(client)
        assertThat(result).isFalse
    }

}