package cube8540.oauth.authentication.rememberme.domain

import cube8540.oauth.authentication.AuthenticationApplication
import org.hibernate.annotations.DynamicUpdate
import org.springframework.data.domain.AbstractAggregateRoot
import java.time.Clock
import java.time.LocalDateTime
import javax.persistence.AttributeOverride
import javax.persistence.Column
import javax.persistence.Embedded
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.Table

@Entity
@Table(name = "remember_me_token")
@DynamicUpdate
class RememberMeToken private constructor(

    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "series", length = 32))
    var series: RememberMeTokenSeries,

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "token", length = 32))
    var tokenValue: RememberMeTokenValue,

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "username", length = 32))
    var username: RememberMePrincipal,

    @Column(name = "registered_at", nullable = false)
    var registeredAt: LocalDateTime,

    @Column(name = "last_used_at", nullable = false)
    var lastUsedAt: LocalDateTime
): AbstractAggregateRoot<RememberMeToken>() {

    companion object {
        @JvmStatic
        @Transient
        protected var clock: Clock = AuthenticationApplication.DEFAULT_CLOCK

        @Transient
        const val tokenValiditySeconds = 1209600.toLong()
    }

    constructor(generator: RememberMeTokenGenerator, username: String): this(
        series = generator.generateTokenSeries(),
        tokenValue = generator.generateTokenValue(),
        username = RememberMePrincipal(username),
        registeredAt = LocalDateTime.now(clock),
        lastUsedAt = LocalDateTime.now(clock))

    fun updateLastUsedAt() {
        this.lastUsedAt = LocalDateTime.now(clock)
    }

    fun isExpired() = lastUsedAt.plusSeconds(tokenValiditySeconds)
        .isBefore(LocalDateTime.now(clock))
}