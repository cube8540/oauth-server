package cube8540.oauth.authentication.error.security

import cube8540.oauth.authentication.error.ExceptionResponseRenderer
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.web.HttpMediaTypeNotSupportedException
import org.springframework.web.context.request.ServletWebRequest

class AccessDeniedExceptionResponseRenderer(private val messageConverter: HttpMessageConverter<Any>): ExceptionResponseRenderer<ErrorMessage<Any>> {
    init {
        if (!messageConverter.canWrite(ErrorMessage::class.java, MediaType.APPLICATION_JSON)) {
            throw HttpMediaTypeNotSupportedException("application/json media type is must be supported")
        }
    }

    override fun rendering(responseEntity: ResponseEntity<ErrorMessage<Any>>, webRequest: ServletWebRequest) {
        ServletServerHttpResponse(webRequest.response!!).use { output ->
            output.setStatusCode(responseEntity.statusCode)
            if (!responseEntity.headers.isEmpty()) {
                output.headers.putAll(responseEntity.headers)
            }

            val body = responseEntity.body
            if (body != null) {
                messageConverter.write(body, MediaType.APPLICATION_JSON, output)
            } else {
                output.body.let {  }
            }
        }
    }
}

class AccessDeniedExceptionTranslator: ExceptionTranslator<ErrorMessage<Any>> {

    override fun translate(exception: Exception): ResponseEntity<ErrorMessage<Any>> =
        ResponseEntity(ErrorMessage.ACCESS_DENIED_ERROR, HttpStatus.FORBIDDEN)

}