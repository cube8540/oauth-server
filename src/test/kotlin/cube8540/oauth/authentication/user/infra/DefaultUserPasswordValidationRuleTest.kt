package cube8540.oauth.authentication.user.infra

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.infra.DefaultUserPasswordValidationRule
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream
import kotlin.random.Random


class DefaultUserPasswordValidationRuleTest {

    private val minPasswordLength = 12
    private val maxPasswordLength = 30
    private val charPool: List<Char> =
        ('a'..'z') + ('0'..'9') + ('A'..'Z') + listOf('#', '?', '!', '@', '$', '%', '^', '&', '*', '-')

    private val rule = DefaultUserPasswordValidationRule()
    private val user: User = mockk()

    @ParameterizedTest
    @MethodSource(value = ["minLengthPasswordProvider", "maxLengthPasswordProvider"])
    fun `password invalid length`(password: String) {
        every { user.password } returns password

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `password exclude uppercase string`() {
        every { user.password } returns "password1234!@#$"

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `password exclude lowercase string`() {
        every { user.password } returns "PASSWORD1234!@#$"

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `password exclude special character`() {
        every { user.password } returns "Password12341234"

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `password include not allowed special character`() {
        every { user.password } returns "Password1234!@#\$."

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `password allowed`() {
        every { user.password } returns "Password1234!@#$"

        val result = rule.isValid(user)
        assertThat(result).isTrue
    }

    private fun minLengthPasswordProvider(): Stream<Arguments> {
        val results = ArrayList<String>()
        for (i in 1 until minPasswordLength) {
            val randomPassword = (1..i)
                .map { Random.nextInt(0, charPool.size) }
                .map(charPool::get)
                .joinToString("")
            results.add(randomPassword)
        }
        return results.map { Arguments.of(it) }.stream()
    }

    private fun maxLengthPasswordProvider(): Stream<Arguments> {
        val randomPassword = (1..(maxPasswordLength + 1))
            .map { Random.nextInt(0, charPool.size) }
            .map(charPool::get)
            .joinToString("")
        return Stream.of(Arguments.of(randomPassword))
    }

}