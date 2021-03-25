package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.security.DefaultOAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DefaultOAuth2RequestValidatorTest {

    private val validator = DefaultOAuth2RequestValidator()

    @Test
    fun `request scope is null`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        val result = validator.validateScopes(clientDetails, null)
        assertThat(result).isTrue
    }

    @Test
    fun `request scope is empty`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        val result = validator.validateScopes(clientDetails, emptySet())
        assertThat(result).isTrue
    }

    @Test
    fun `client does not has request scope`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        val result = validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3", "scope-4"))
        assertThat(result).isFalse
    }

    @Test
    fun `client has request scope`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        val result = validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3"))
        assertThat(result).isTrue
    }

}