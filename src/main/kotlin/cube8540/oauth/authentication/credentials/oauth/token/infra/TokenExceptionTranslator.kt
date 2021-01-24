package cube8540.oauth.authentication.credentials.oauth.token.infra

import cube8540.oauth.authentication.credentials.oauth.token.domain.TokenAccessDeniedException
import cube8540.oauth.authentication.credentials.oauth.token.domain.TokenNotFoundException
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component

@Component
class TokenExceptionTranslator: ExceptionTranslator<ErrorMessage<Any>> {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    override fun translate(exception: Exception): ResponseEntity<ErrorMessage<Any>> = when (exception) {
        is TokenNotFoundException -> {
            response(HttpStatus.NOT_FOUND, ErrorMessage.instance(exception.code, exception.message))
        }
        is TokenAccessDeniedException -> {
            response(HttpStatus.FORBIDDEN, ErrorMessage.instance(exception.code, exception.message))
        }
        else -> {
            logger.error("Handle exception {} {}", exception.javaClass, exception.message)
            response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR)
        }
    }
}