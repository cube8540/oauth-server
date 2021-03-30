package cube8540.oauth.authentication.oauth.security.provider

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.util.*

class ClientCredentialsTokenTest {

    @Test
    fun `without authorities`() {
        val token = ClientCredentialsToken("clientId", "clientSecret")

        assertThat(token.principal).isEqualTo("clientId")
        assertThat(token.credentials).isEqualTo("clientSecret")
        assertThat(token.authorities).isEqualTo(emptyList<GrantedAuthority>())
        assertThat(token.isAuthenticated).isFalse
    }

    @Test
    fun `with authorities`() {
        val authorities = listOf(SimpleGrantedAuthority("authority-1"), SimpleGrantedAuthority("authority-2"))
        val token = ClientCredentialsToken("clientId", "clientSecret", authorities)

        assertThat(token.principal).isEqualTo("clientId")
        assertThat(token.credentials).isEqualTo("clientSecret")
        assertThat(token.authorities).isEqualTo(Collections.unmodifiableList(authorities))
        assertThat(token.isAuthenticated).isTrue
    }

    @Test
    fun `set authorities`() {
        val token = ClientCredentialsToken("clientId", "clientSecret")

        val thrown = catchThrowable { token.isAuthenticated = true }
        assertThat(thrown).isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `get principal name when type is string`() {
        val token = ClientCredentialsToken("clientId", "clientSecret")

        assertThat(token.name).isEqualTo("clientId")
    }

    @Test
    fun `get principal name when type is client details`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
        }
        val token = ClientCredentialsToken(clientDetails, "clientSecret")

        assertThat(token.name).isEqualTo("clientId")
    }

    @Test
    fun `erase sensitive data`() {
        val token = ClientCredentialsToken("clientId", "clientSecret")

        token.eraseCredentials()
        assertThat(token.credentials).isNull()
    }
}