package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

class WithScopeComposeUniqueKeyGeneratorTest {

    private val keyGenerator = WithScopeComposeUniqueKeyGenerator()

    @Test
    fun `generate compose key`() {
        val accessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns PrincipalUsername("username")
            every { client } returns OAuth2ClientId("clientId")
            every { scopes } returns LinkedHashSet(listOf(AuthorityCode("scope-2"), AuthorityCode("scope-1")))
        }
        val expectedValue: MutableMap<String, String> = LinkedHashMap()

        expectedValue[WithScopeComposeUniqueKeyGenerator.USERNAME_KEY] = "username"
        expectedValue[WithScopeComposeUniqueKeyGenerator.CLIENT_KEY] = "clientId"
        expectedValue[WithScopeComposeUniqueKeyGenerator.SCOPE_KEY] = "[scope-1, scope-2]"
        val expectedKeyValue = md5(expectedValue.toString())

        val result = keyGenerator.generateKey(accessToken)
        assertThat(result.value).isEqualTo(expectedKeyValue)
    }

    @Test
    fun `generate client credentials access token compose key`() {
        val accessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns null
            every { client } returns OAuth2ClientId("clientId")
            every { scopes } returns LinkedHashSet(listOf(AuthorityCode("scope-2"), AuthorityCode("scope-1")))
        }
        val expectedValue: MutableMap<String, String> = LinkedHashMap()

        expectedValue[WithScopeComposeUniqueKeyGenerator.CLIENT_KEY] = "clientId"
        expectedValue[WithScopeComposeUniqueKeyGenerator.SCOPE_KEY] = "[scope-1, scope-2]"
        val expectedKeyValue = md5(expectedValue.toString())

        val result = keyGenerator.generateKey(accessToken)
        assertThat(result.value).isEqualTo(expectedKeyValue)
    }

    private fun md5(value: String): String {
        try {
            val digest = MessageDigest.getInstance("MD5")
            val bytes = digest.digest(value.toByteArray(StandardCharsets.UTF_8))
            return String.format("%032x", BigInteger(1, bytes))
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        }
    }
}