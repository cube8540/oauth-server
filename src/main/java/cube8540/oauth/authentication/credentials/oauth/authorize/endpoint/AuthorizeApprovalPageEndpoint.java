package cube8540.oauth.authentication.credentials.oauth.authorize.endpoint;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AuthorizeApprovalPageEndpoint {

    @GetMapping(value = "/oauth/approval")
    public ModelAndView approval() {
        return new ModelAndView("oauth/approval");
    }

}
