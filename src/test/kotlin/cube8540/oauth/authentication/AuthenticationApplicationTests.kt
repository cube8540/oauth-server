package cube8540.oauth.authentication

import java.util.TimeZone
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

@SpringBootTest
@ActiveProfiles("test")
class AuthenticationApplicationTests {

    @Test
    fun `context load`() {
        assertEquals(TimeZone.getTimeZone("Asia/Seoul"), TimeZone.getDefault())
    }
}