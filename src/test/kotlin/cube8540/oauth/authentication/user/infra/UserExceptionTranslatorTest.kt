package cube8540.oauth.authentication.user.infra

import cube8540.oauth.authentication.users.domain.UserAuthorizationException
import cube8540.oauth.authentication.users.domain.UserInvalidException
import cube8540.oauth.authentication.users.domain.UserNotFoundException
import cube8540.oauth.authentication.users.domain.UserRegisterException
import cube8540.oauth.authentication.users.infra.UserExceptionTranslator
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import java.util.*
import java.util.stream.Stream

class UserExceptionTranslatorTest {

    private val translator = UserExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["userNotFoundExceptions"])
    fun `translate user not found exception`(exception: UserNotFoundException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @ParameterizedTest
    @MethodSource(value = ["userInvalidExceptions"])
    fun `translate user invalid exception`(exception: UserInvalidException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @ParameterizedTest
    @MethodSource(value = ["userRegisterExceptions"])
    fun `translate user register exception`(exception: UserRegisterException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @ParameterizedTest
    @MethodSource(value = ["userAuthorizationExceptions"])
    fun `translate user authorization exception`(exception: UserAuthorizationException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    fun userNotFoundExceptions() = Stream.of(
        Arguments.of(UserNotFoundException.instance("user not found"))
    )

    fun userInvalidExceptions() = Stream.of(
        Arguments.of(UserInvalidException.instance(Collections.emptyList()))
    )

    fun userRegisterExceptions() = Stream.of(
        Arguments.of(UserRegisterException.existsIdentifier("exists identifier"))
    )

    fun userAuthorizationExceptions() = Stream.of(
        Arguments.of(UserAuthorizationException.alreadyCredentials("already credentials")),
        Arguments.of(UserAuthorizationException.invalidKey("invalid key")),
        Arguments.of(UserAuthorizationException.invalidPassword("invalid password")),
        Arguments.of(UserAuthorizationException.keyExpired("key expired"))
    )
}