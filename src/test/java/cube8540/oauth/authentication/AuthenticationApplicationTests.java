package cube8540.oauth.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
@DisplayName("스프링 컨테이너 테스트")
class AuthenticationApplicationTests {

    @Test
    @DisplayName("스프링 컨테이너 로딩")
    void contextLoads() {
    }

}
