package cube8540.oauth.authentication.oauth.token.infra

import cube8540.oauth.authentication.oauth.token.domain.TokenAccessDeniedException
import cube8540.oauth.authentication.oauth.token.domain.TokenNotFoundException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.springframework.http.HttpStatus
import java.util.stream.Stream

class TokenExceptionTranslatorTest {

    private val translator: TokenExceptionTranslator = TokenExceptionTranslator()

    @ParameterizedTest
    @MethodSource(value = ["tokenAccessDeniedException"])
    fun `translate token access denied exception`(exception: TokenAccessDeniedException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.FORBIDDEN)
    }

    @ParameterizedTest
    @MethodSource(value = ["tokenNotFoundException"])
    fun `translate token not found exception`(exception: TokenNotFoundException) {
        val result = translator.translate(exception)

        assertThat(result.statusCode).isEqualTo(HttpStatus.NOT_FOUND)
    }

    private fun tokenAccessDeniedException() = Stream.of(
        Arguments.of(TokenAccessDeniedException.denied("denied"))
    )

    private fun tokenNotFoundException() = Stream.of(
        Arguments.of(TokenNotFoundException.instance("not found"))
    )
}