package cube8540.oauth.authentication

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.context.annotation.EnableAspectJAutoProxy
import org.springframework.retry.annotation.EnableRetry
import java.time.Clock
import java.time.ZoneOffset
import java.util.*
import javax.annotation.PostConstruct


@EnableRetry
@EnableAspectJAutoProxy
@SpringBootApplication
class AuthenticationApplication {

    companion object {
        @JvmField
        val DEFAULT_ZONE_OFFSET: ZoneOffset = ZoneOffset.of("+09:00")

        @JvmField
        val DEFAULT_TIME_ZONE: TimeZone = TimeZone.getTimeZone("Asia/Seoul")

        @JvmField
        val DEFAULT_CLOCK: Clock = Clock.system(DEFAULT_TIME_ZONE.toZoneId())
    }

    @PostConstruct
    fun systemSetup() {
        TimeZone.setDefault(DEFAULT_TIME_ZONE)
    }
}

fun main(args: Array<String>) {
    SpringApplication.run(AuthenticationApplication::class.java, *args)
}