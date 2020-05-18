package cube8540.oauth.authentication.credentials.role;

import cube8540.oauth.authentication.credentials.role.application.DefaultRoleManagementService;
import cube8540.oauth.authentication.credentials.role.application.RoleManagementService;
import cube8540.oauth.authentication.credentials.role.domain.RoleRepository;
import cube8540.oauth.authentication.credentials.role.infra.DefaultRoleValidationPolicy;
import cube8540.oauth.authentication.credentials.role.infra.RoleExceptionTranslator;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RoleConfiguration {

    @Setter(onMethod_ = @Autowired)
    private RoleRepository roleRepository;

    @Bean
    public RoleManagementService defaultRoleManagementService() {
        DefaultRoleManagementService service = new DefaultRoleManagementService(roleRepository);

        DefaultRoleValidationPolicy policy = new DefaultRoleValidationPolicy();
        service.setValidationPolicy(policy);

        return service;
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<Object>> roleExceptionTranslator() {
        return new RoleExceptionTranslator();

    }
}
