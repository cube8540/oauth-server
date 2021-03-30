package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.ClientAuthorizationException
import cube8540.oauth.authentication.oauth.client.domain.ClientInvalidException
import cube8540.oauth.authentication.oauth.client.domain.ClientNotFoundException
import cube8540.oauth.authentication.oauth.client.domain.ClientRegisterException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import java.util.stream.Stream

class ClientAPIExceptionTranslatorTest {

    private val translator = ClientAPIExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["clientAuthorizationException"])
    fun `translate client authorization exception`(exception: ClientAuthorizationException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @ParameterizedTest
    @MethodSource(value = ["clientInvalidException"])
    fun `translate client invalid exception`(exception: ClientInvalidException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @ParameterizedTest
    @MethodSource(value = ["clientNotFoundException"])
    fun `translate client not found exception`(exception: ClientNotFoundException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @ParameterizedTest
    @MethodSource(value = ["clientRegisterException"])
    fun `translate client register exception`(exception: ClientRegisterException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    fun clientAuthorizationException() = Stream.of(
        Arguments.of(ClientAuthorizationException.invalidPassword("password"))
    )

    fun clientInvalidException() = Stream.of(
        Arguments.of(ClientInvalidException.instance(emptyList()))
    )

    fun clientNotFoundException() = Stream.of(
        Arguments.of(ClientNotFoundException.instance("not found"))
    )

    fun clientRegisterException() = Stream.of(
        Arguments.of(ClientRegisterException.existsIdentifier("exists identifier"))
    )

}