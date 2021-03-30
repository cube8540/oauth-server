package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.ResourceInvalidException
import cube8540.oauth.authentication.resource.domain.ResourceNotFoundException
import cube8540.oauth.authentication.resource.domain.ResourceRegisterException
import org.assertj.core.api.Assertions
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import java.util.stream.Stream

class SecuredResourceExceptionTranslatorTest {

    private val translator = SecuredResourceExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["resourceNotFoundExceptions"])
    fun `translate resource not found exception`(exception: ResourceNotFoundException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.NOT_FOUND)
    }

    @ParameterizedTest
    @MethodSource(value = ["resourceRegisterExceptions"])
    fun `translate resource register exception`(exception: ResourceRegisterException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    @ParameterizedTest
    @MethodSource(value = ["resourceInvalidExceptions"])
    fun `translate resource invalid exception`(exception: ResourceInvalidException) {
        val result = translator.translate(exception)
        assertThat(result.statusCode).isEqualTo(HttpStatus.BAD_REQUEST)
    }

    fun resourceNotFoundExceptions() = Stream.of(
        Arguments.of(ResourceNotFoundException.instance("resource not found"))
    )

    fun resourceRegisterExceptions() = Stream.of(
        Arguments.of(ResourceRegisterException.existsIdentifier("exists identifier"))
    )

    fun resourceInvalidExceptions() = Stream.of(
        Arguments.of(ResourceInvalidException.instance(emptyList()))
    )

}