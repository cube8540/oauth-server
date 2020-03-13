package cube8540.oauth.authentication.users;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.infra.UserExceptionTranslator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.io.Serializable;

@Configuration
public class UserConfiguration {

    @Bean
    @Primary
    public UserCredentialsKeyGenerator userCredentialsKeyGenerator() {
        return new DefaultUserCredentialsKeyGenerator();
    }

    @Bean
    public ExceptionTranslator<ErrorMessage<? extends Serializable>> userExceptionTranslator() {
        return new UserExceptionTranslator();
    }

}
