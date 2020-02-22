package cube8540.oauth.authentication;

import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator;
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.annotation.PostConstruct;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.TimeZone;

@SpringBootApplication
public class AuthenticationApplication {

    public static final ZoneOffset DEFAULT_ZONE_OFFSET = ZoneOffset.of("+09:00");

    public static final TimeZone DEFAULT_TIME_ZONE = TimeZone.getTimeZone("Asia/Seoul");

    public static final Clock DEFAULT_CLOCK = Clock.system(DEFAULT_TIME_ZONE.toZoneId());

    @PostConstruct
    void systemSetup() {
        TimeZone.setDefault(DEFAULT_TIME_ZONE);
    }

    @Bean
    @Primary
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Primary
    public UserCredentialsKeyGenerator userCredentialsKeyGenerator() {
        return new DefaultUserCredentialsKeyGenerator();
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationApplication.class, args);
    }

}
