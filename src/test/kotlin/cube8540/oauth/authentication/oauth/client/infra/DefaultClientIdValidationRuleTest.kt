package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class DefaultClientIdValidationRuleTest {
    private val minClientIdLength = 8
    private val maxClientIdLength = 30

    private val charPool: List<Char> = ('a'..'z') + ('0'..'9') + listOf('-', '_')
    private val client: OAuth2Client = mockk()

    private val rule = DefaultClientIdValidationRule()

    @ParameterizedTest
    @MethodSource(value = ["minLengthClientIdProvider", "maxLengthClientIdProvider"])
    fun `client id invalid length`(clientId: OAuth2ClientId) {
        every { client.clientId } returns clientId

        val result = rule.isValid(client)
        assertThat(result).isFalse
    }

    @Test
    fun `client id include not allowed special character`() {
        val clientId = OAuth2ClientId("clientId!@#")

        every { client.clientId } returns clientId

        val result = rule.isValid(client)
        assertThat(result).isFalse
    }

    private fun minLengthClientIdProvider(): Stream<Arguments> {
        val results = ArrayList<OAuth2ClientId>()
        for (i in 1 until minClientIdLength) {
            val clientId = (1..i)
                .map { charPool.random() }
                .joinToString("")
            results.add(OAuth2ClientId(clientId))
        }
        return results.map { Arguments.of(it) }.stream()
    }

    private fun maxLengthClientIdProvider(): Stream<Arguments> {
        val clientId = (1..(maxClientIdLength + 1))
            .map { charPool.random() }
            .joinToString("")
        return Stream.of(Arguments.of(OAuth2ClientId(clientId)))
    }
}