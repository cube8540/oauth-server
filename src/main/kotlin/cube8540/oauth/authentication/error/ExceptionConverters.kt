package cube8540.oauth.authentication.error

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.context.request.ServletWebRequest
import java.io.IOException
import javax.servlet.ServletException

interface ExceptionTranslator<T> {

    @JvmDefault
    fun <B> response(status: HttpStatus, body: B): ResponseEntity<B> = ResponseEntity(body, status)

    fun translate(exception: Exception): ResponseEntity<T>

}

interface ExceptionResponseRenderer<T> {

    @Throws(IOException::class, ServletException::class)
    fun rendering(responseEntity: ResponseEntity<T>, webRequest: ServletWebRequest)

}