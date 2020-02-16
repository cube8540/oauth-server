package cube8540.oauth.authentication;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/accounts/signin").setViewName("accounts/signin");
        registry.addViewController("/oauth/approval").setViewName("oauth/approval");
    }
}
