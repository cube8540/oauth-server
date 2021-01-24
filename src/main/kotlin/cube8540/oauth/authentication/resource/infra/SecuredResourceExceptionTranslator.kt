package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.resource.domain.ResourceInvalidException
import cube8540.oauth.authentication.resource.domain.ResourceNotFoundException
import cube8540.oauth.authentication.resource.domain.ResourceRegisterException
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Component

@Component
class SecuredResourceExceptionTranslator: ExceptionTranslator<ErrorMessage<Any>> {

    private val logger = LoggerFactory.getLogger(this::class.java)

    override fun translate(exception: Exception): ResponseEntity<ErrorMessage<Any>> = when(exception) {
        is ResourceNotFoundException -> {
            ResponseEntity(ErrorMessage.instance(exception.code, exception.message), HttpStatus.NOT_FOUND)
        }
        is ResourceRegisterException -> {
            ResponseEntity(ErrorMessage.instance(exception.code, exception.message), HttpStatus.BAD_REQUEST)
        }
        is ResourceInvalidException -> {
            ResponseEntity(ErrorMessage.instance(exception.code, exception.errors), HttpStatus.BAD_REQUEST)
        }
        else -> {
            logger.error("Handle exception {} {}", exception.javaClass, exception.message)
            response(HttpStatus.INTERNAL_SERVER_ERROR, ErrorMessage.UNKNOWN_SERVER_ERROR)
        }
    }
}