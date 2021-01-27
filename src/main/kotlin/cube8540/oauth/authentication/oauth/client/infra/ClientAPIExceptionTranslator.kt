package cube8540.oauth.authentication.oauth.client.infra

import cube8540.oauth.authentication.oauth.client.domain.ClientAuthorizationException
import cube8540.oauth.authentication.oauth.client.domain.ClientInvalidException
import cube8540.oauth.authentication.oauth.client.domain.ClientNotFoundException
import cube8540.oauth.authentication.oauth.client.domain.ClientRegisterException
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component

@Component
class ClientAPIExceptionTranslator: ExceptionTranslator<ErrorMessage<Any>> {

    private val logger = LoggerFactory.getLogger(this.javaClass)

    override fun translate(exception: Exception): ResponseEntity<ErrorMessage<Any>> = when (exception) {
        is ClientNotFoundException -> {
            response(HttpStatus.NOT_FOUND, ErrorMessage.instance(exception.code, exception.message))
        }
        is ClientInvalidException -> {
            response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(exception.code, exception.errors.toTypedArray()))
        }
        is ClientRegisterException -> {
            response(HttpStatus.BAD_REQUEST, ErrorMessage.instance(exception.code, exception.message))
        }
        is ClientAuthorizationException -> {
            response(HttpStatus.FORBIDDEN, ErrorMessage.instance(exception.code, exception.message))
        }
        else -> {
            logger.error("Handle exception {} {}", exception.javaClass, exception.message)
            response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR)
        }
    }
}