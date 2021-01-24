package cube8540.oauth.authentication.oauth.scope.infra

import cube8540.oauth.authentication.oauth.scope.domain.ScopeInvalidException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeNotFoundException
import cube8540.oauth.authentication.oauth.scope.domain.ScopeRegisterException
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component

@Component
class ScopeAPIExceptionTranslator: ExceptionTranslator<ErrorMessage<Any>> {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    override fun translate(exception: Exception): ResponseEntity<ErrorMessage<Any>> = when (exception) {
        is ScopeInvalidException -> {
            response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(exception.code, exception.errors.toTypedArray()))
        }
        is ScopeRegisterException -> {
            response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(exception.code, exception.message))
        }
        is ScopeNotFoundException -> {
            response(HttpStatus.NOT_FOUND, ErrorMessage.instance(exception.code, exception.message))
        }
        else -> {
            logger.error("Handle exception {} {}", exception.javaClass, exception.message)
            response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR)
        }
    }
}