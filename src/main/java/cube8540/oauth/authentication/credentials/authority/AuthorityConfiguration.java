package cube8540.oauth.authentication.credentials.authority;

import cube8540.oauth.authentication.credentials.authority.application.DefaultSecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceRepository;
import cube8540.oauth.authentication.credentials.authority.infra.AuthorityExceptionTranslator;
import cube8540.oauth.authentication.credentials.authority.infra.DefaultSecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.SecuredResourceExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.Serializable;

@Configuration
public class AuthorityConfiguration {

    @Bean
    @Autowired
    public SecuredResourceManagementService securedResourceManagementService(SecuredResourceRepository securedResourceRepository) {
        DefaultSecuredResourceManagementService service = new DefaultSecuredResourceManagementService(securedResourceRepository);

        service.setPolicy(new DefaultSecuredResourceValidationPolicy());
        return service;
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<? extends Serializable>> authorityExceptionTranslator() {
        return new AuthorityExceptionTranslator();
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<? extends Serializable>> securedResourceExceptionTranslator() {
        return new SecuredResourceExceptionTranslator();
    }

}
