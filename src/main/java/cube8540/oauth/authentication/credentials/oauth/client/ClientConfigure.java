package cube8540.oauth.authentication.credentials.oauth.client;

import cube8540.oauth.authentication.credentials.oauth.client.application.DefaultOAuth2ClientManagementService;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientManagementService;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientRepository;
import cube8540.oauth.authentication.credentials.oauth.client.infra.DefaultOAuth2ClientValidatePolicy;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2AccessibleScopeDetailsService;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ClientConfigure {

    @Setter(onMethod_ = @Autowired)
    private OAuth2ClientRepository repository;

    @Setter(onMethod_ = @Autowired)
    private PasswordEncoder passwordEncoder;

    @Setter(onMethod_ = @Autowired)
    private OAuth2AccessibleScopeDetailsService scopeDetailsService;

    @Bean
    public OAuth2ClientManagementService clientManagementService() {
        DefaultOAuth2ClientManagementService service = new DefaultOAuth2ClientManagementService(repository);
        DefaultOAuth2ClientValidatePolicy policy = new DefaultOAuth2ClientValidatePolicy();

        policy.setScopeDetailsService(scopeDetailsService);
        service.setPasswordEncoder(passwordEncoder);
        service.setValidatePolicy(policy);
        return service;
    }

}
