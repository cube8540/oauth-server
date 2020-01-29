package cube8540.oauth.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import java.util.TimeZone;

@SpringBootApplication
public class AuthenticationApplication {

    public static final TimeZone DEFAULT_TIME_ZONE = TimeZone.getTimeZone("Asia/Seoul");

    @PostConstruct
    void systemSetup() {
        TimeZone.setDefault(DEFAULT_TIME_ZONE);
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthenticationApplication.class, args);
    }

}
