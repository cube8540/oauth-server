package cube8540.oauth.authentication;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

@Controller
public class ErrorHandlingController implements ErrorController {

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping(value = "/error")
    public String errorPage(HttpServletRequest request, Model model) {
        String status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE).toString();

        HttpStatus statusCode = HttpStatus.valueOf(Integer.parseInt(status));
        model.addAttribute("status", statusCode.value());
        if (statusCode.equals(HttpStatus.NOT_FOUND)) {
            return "error/404";
        }
        return "error/error";
    }
}
