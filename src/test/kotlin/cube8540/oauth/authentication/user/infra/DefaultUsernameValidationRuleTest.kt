package cube8540.oauth.authentication.user.infra

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.Username
import cube8540.oauth.authentication.users.infra.DefaultUsernameValidationRule
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream


class DefaultUsernameValidationRuleTest {

    private val minUsernameLength = 4
    private val maxUsernameLength = 18
    private val charPool: List<Char> = ('a'..'z') + ('0'..'9')
    private val numberPool: IntRange = (0..9)
    private val characterPool: CharRange = ('a'..'z')

    private val rule: DefaultUsernameValidationRule = DefaultUsernameValidationRule()
    private val user: User = mockk()

    @ParameterizedTest
    @MethodSource(value = ["minLengthUsernameProvider", "maxLengthUsernameProvider"])
    fun `username invalid length`(username: Username) {
        every { user.username } returns username

        assertThat(rule.isValid(user)).isFalse
    }

    @ParameterizedTest
    @MethodSource(value = ["characterOnlyProvider"])
    fun `username exclude number`(username: Username) {
        every { user.username } returns username

        assertThat(rule.isValid(user)).isFalse
    }

    @ParameterizedTest
    @MethodSource(value = ["numberOnlyProvider"])
    fun `username exclude character`(username: Username) {
        every { user.username } returns username

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `username included spacial character`() {
        every { user.username } returns Username("username!@#1234")

        assertThat(rule.isValid(user)).isFalse
    }

    @Test
    fun `username allowed`() {
        every { user.username } returns Username("username1234")

        assertThat(rule.isValid(user)).isTrue
    }

    private fun minLengthUsernameProvider(): Stream<Arguments> {
        val results = ArrayList<Username>()
        for (i in 1 until minUsernameLength) {
            val randomUsername = (1..i)
                .map { charPool.random() }
                .joinToString("")
            results.add(Username(randomUsername))
        }
        return results.map { Arguments.of(it) }.stream()
    }

    private fun maxLengthUsernameProvider(): Stream<Arguments> {
        val randomUsername = (1..(maxUsernameLength + 1))
            .map { charPool.random() }
            .joinToString("")
        return Stream.of(Arguments.of(Username(randomUsername)))
    }

    private fun characterOnlyProvider(): Stream<Arguments> {
        val results = ArrayList<Username>()
        for (i in minUsernameLength..maxUsernameLength) {
            val randomUsername = (0..i)
                .map { characterPool.random() }
                .joinToString("")
            results.add(Username(randomUsername))
        }
        return results.map { Arguments.of(it) }.stream()
    }

    private fun numberOnlyProvider(): Stream<Arguments> {
        val results = ArrayList<Username>()
        for (i in minUsernameLength..maxUsernameLength) {
            val randomUsername = (0..i)
                .map { numberPool.random() }
                .joinToString("")
            results.add(Username(randomUsername))
        }
        return results.map { Arguments.of(it) }.stream()
    }
}