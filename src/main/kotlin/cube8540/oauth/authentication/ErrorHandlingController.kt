package cube8540.oauth.authentication

import cube8540.oauth.authentication.error.message.ErrorCodes
import cube8540.oauth.authentication.error.message.ErrorMessage
import org.springframework.boot.web.servlet.error.ErrorController
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import javax.servlet.RequestDispatcher
import javax.servlet.http.HttpServletRequest

@Controller
class ErrorHandlingController: ErrorController {

    override fun getErrorPath(): String = "/error"

    @GetMapping(value = ["/error"], produces = [MediaType.TEXT_HTML_VALUE])
    fun errorPage(request: HttpServletRequest, model: Model): String {
        val status = getErrorStatusCode(request)

        model.addAttribute("status", status.value())
        if (status == HttpStatus.NOT_FOUND) {
            return "error/404"
        }
        return "error/error"
    }

    @GetMapping(value = ["/error"], produces = [MediaType.APPLICATION_JSON_VALUE])
    fun errorMessage(request: HttpServletRequest): ResponseEntity<ErrorMessage<Any>> {
        val status = getErrorStatusCode(request)

        if (status == HttpStatus.NOT_FOUND) {
            return ResponseEntity(ErrorMessage.instance(ErrorCodes.NOT_FOUND, "Page not found"), status)
        }
        return ResponseEntity(ErrorMessage.UNKNOWN_SERVER_ERROR, status)
    }

    fun getErrorStatusCode(request: HttpServletRequest): HttpStatus =
        HttpStatus.valueOf(request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE).toString().toInt())
}