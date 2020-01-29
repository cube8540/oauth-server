package cube8540.oauth.authentication;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@ActiveProfiles("test")
@DisplayName("스프링 컨테이너 테스트")
class AuthenticationApplicationTests {

    @Test
    @DisplayName("스프링 컨테이너 로딩")
    void contextLoads() {
    }

    @Test
    @DisplayName("TimeZone이 Asia/Seoul로 설정되어있어야 한다.")
    void shouldTimeZoneSetAsiaSeoul() {
        assertEquals(TimeZone.getTimeZone("Asia/Seoul"), TimeZone.getDefault());
    }

}
