package cube8540.oauth.authentication.oauth.scope.infra

import cube8540.oauth.authentication.oauth.scope.domain.ScopeInvalidException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeNotFoundException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeRegisterException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import java.util.stream.Stream

class ScopeAPIExceptionTranslatorTest {

    private val translator = ScopeAPIExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["scopeInvalidException"])
    fun `translator scope invalid exception`(exception: ScopeInvalidException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @ParameterizedTest
    @MethodSource(value = ["scopeNotFoundException"])
    fun `translator scope not found exception`(exception: ScopeNotFoundException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @ParameterizedTest
    @MethodSource(value = ["scopeRegisterException"])
    fun `translator scope register exception`(exception: ScopeRegisterException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    fun scopeInvalidException() = Stream.of(
        Arguments.of(ScopeInvalidException.instance(emptyList()))
    )

    fun scopeNotFoundException() = Stream.of(
        Arguments.of(ScopeNotFoundException.instance("scope not found"))
    )

    fun scopeRegisterException() = Stream.of(
        Arguments.of(ScopeRegisterException.existsIdentifier("exists identifier"))
    )
}