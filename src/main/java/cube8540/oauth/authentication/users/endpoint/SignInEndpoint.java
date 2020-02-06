package cube8540.oauth.authentication.users.endpoint;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class SignInEndpoint {

    @GetMapping(value = "/accounts/signin")
    public ModelAndView signIn() {
        return new ModelAndView("accounts/signin");
    }

}
