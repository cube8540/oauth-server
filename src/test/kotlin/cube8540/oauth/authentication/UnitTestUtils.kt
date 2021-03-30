package cube8540.oauth.authentication

import org.springframework.security.core.AuthenticationException
import java.time.Instant
import java.time.LocalDateTime

fun LocalDateTime.toDefaultInstance(): Instant = this.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET)

class UnitTestValidationException: RuntimeException()

class UnitTestAuthenticationException(message: String): AuthenticationException(message)