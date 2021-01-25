package cube8540.oauth.authentication.oauth.error

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import cube8540.oauth.authentication.oauth.ErrorMessageKey
import cube8540.oauth.authentication.error.ExceptionResponseRenderer
import cube8540.oauth.authentication.error.ExceptionTranslator
import org.springframework.http.CacheControl
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.server.ServletServerHttpResponse
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.stereotype.Component
import org.springframework.web.HttpMediaTypeNotSupportedException
import org.springframework.web.HttpRequestMethodNotSupportedException
import org.springframework.web.context.request.ServletWebRequest

private const val METHOD_ALLOWED = 405
private const val UNAUTHORIZED = 401
private const val BAD_REQUEST = 400
private const val SERVER_ERROR = 500

class OAuth2ErrorSerializer: StdSerializer<OAuth2Error>(OAuth2Error::class.java) {

    override fun serialize(value: OAuth2Error, gen: JsonGenerator, provider: SerializerProvider) {
        gen.writeStartObject()
        gen.writeStringField(ErrorMessageKey.ERROR, value.errorCode)
        gen.writeStringField(ErrorMessageKey.DESCRIPTION, value.description)
        gen.writeEndObject()
    }
}

@Component
class OAuth2ExceptionTranslator: ExceptionTranslator<OAuth2Error> {

    override fun translate(exception: Exception): ResponseEntity<OAuth2Error> = when(exception) {
        is AbstractOAuth2AuthenticationException -> {
            createResponseEntity(exception)
        }
        is HttpRequestMethodNotSupportedException -> {
            createResponseEntity(MethodNotAllowedException(exception.message))
        }
        is OAuth2ClientRegistrationException -> {
            createResponseEntity(ClientAuthenticationException(exception.message))
        }
        is OAuth2AccessTokenRegistrationException -> {
            createResponseEntity(TokenNotFoundException(exception.message))
        }
        else -> {
            createResponseEntity(ServerErrorException(exception.message))
        }
    }

    private fun createResponseEntity(e: AbstractOAuth2AuthenticationException): ResponseEntity<OAuth2Error> {
        val headers = HttpHeaders()
        headers.setCacheControl(CacheControl.noStore())
        headers.pragma = "no-cache"

        return ResponseEntity(e.error, headers, HttpStatus.valueOf(e.statusCode))
    }
}

class OAuth2ExceptionResponseRenderer(private val converter: HttpMessageConverter<Any>, private val supportedMediaType: MediaType):
    ExceptionResponseRenderer<OAuth2Error> {

    init {
        if (!converter.canWrite(OAuth2Error::class.java, supportedMediaType)) {
            throw HttpMediaTypeNotSupportedException("$supportedMediaType is not supported")
        }
    }

    constructor(converter: HttpMessageConverter<Any>): this(converter, MediaType.ALL)

    override fun rendering(responseEntity: ResponseEntity<OAuth2Error>, webRequest: ServletWebRequest) {
        ServletServerHttpResponse(webRequest.response!!).use {
            it.setStatusCode(responseEntity.statusCode)
            if (!responseEntity.headers.isEmpty()) {
                it.headers.putAll(responseEntity.headers)
            }

            val body = responseEntity.body
            if (body != null) {
                converter.write(body, supportedMediaType, it)
            } else {
                it.body.let {  }
            }
        }
    }
}

private class MethodNotAllowedException(message: String?):
    AbstractOAuth2AuthenticationException(METHOD_ALLOWED, OAuth2Error("method_not_allowed", message, null))

private class ClientAuthenticationException(message: String?):
    AbstractOAuth2AuthenticationException(UNAUTHORIZED, OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, message, null))

private class TokenNotFoundException(message: String?):
    AbstractOAuth2AuthenticationException(BAD_REQUEST, OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, message, null))

private class ServerErrorException(message: String?):
    AbstractOAuth2AuthenticationException(SERVER_ERROR, OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, message, null))