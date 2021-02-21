package cube8540.oauth.authentication

import java.time.Instant
import java.time.LocalDateTime


fun LocalDateTime.toDefaultInstance(): Instant = this.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET)