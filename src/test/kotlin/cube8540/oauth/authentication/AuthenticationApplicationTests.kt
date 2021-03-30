package cube8540.oauth.authentication

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import java.util.*

@SpringBootTest
@ActiveProfiles("test")
class AuthenticationApplicationTests {

    @Test
    fun `context load`() {
        assertEquals(TimeZone.getTimeZone("Asia/Seoul"), TimeZone.getDefault())
    }
}