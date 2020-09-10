package cube8540.oauth.authentication;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

@Controller
public class ErrorHandlingController implements ErrorController {

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @GetMapping(value = "/error", produces = MediaType.TEXT_HTML_VALUE)
    public String errorPage(HttpServletRequest request, Model model) {
        HttpStatus statusCode = getErrorStatusCode(request);
        model.addAttribute("status", statusCode.value());
        if (statusCode.equals(HttpStatus.NOT_FOUND)) {
            return "error/404";
        }
        return "error/error";
    }

    @GetMapping(value = "/error", produces = {MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ErrorMessage<Object>> errorMessage(HttpServletRequest request) {
        HttpStatus statusCode = getErrorStatusCode(request);
        if (statusCode.equals(HttpStatus.NOT_FOUND)) {
            return new ResponseEntity<>(ErrorMessage.instance(ErrorCodes.NOT_FOUND, "Page not found"), statusCode);
        }
        return new ResponseEntity<>(ErrorMessage.UNKNOWN_SERVER_ERROR, statusCode);
    }

    private HttpStatus getErrorStatusCode(HttpServletRequest request) {
        String status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE).toString();

        return HttpStatus.valueOf(Integer.parseInt(status));
    }
}
