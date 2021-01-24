package cube8540.oauth.authentication.credentials.oauth.token.domain

import cube8540.oauth.authentication.AuthenticationApplication
import org.springframework.data.domain.AbstractAggregateRoot
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime
import javax.persistence.AttributeOverride
import javax.persistence.CascadeType
import javax.persistence.Column
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.OneToOne
import javax.persistence.Table
import javax.persistence.Transient

@Entity
@Table(name = "oauth2_refresh_token")
class OAuth2AuthorizedRefreshToken(
    @Transient
    private val tokenIdGenerator: OAuth2TokenIdGenerator,

    @Column(name = "expiration", nullable = false)
    var expiration: LocalDateTime,

    @OneToOne(fetch = FetchType.EAGER, cascade = [CascadeType.ALL])
    var accessToken: OAuth2AuthorizedAccessToken
): AbstractAggregateRoot<OAuth2AuthorizedRefreshToken>() {

    companion object {
        @JvmStatic
        @Transient
        protected var clock: Clock = AuthenticationApplication.DEFAULT_CLOCK
    }

    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "token_id", length = 32))
    var tokenId: OAuth2TokenId = tokenIdGenerator.generateTokenValue()

    fun isExpired(): Boolean = this.expiration.isBefore(LocalDateTime.now(clock))

    fun expiresIn(): Long {
        if (isExpired()) {
            return 0
        }
        return Duration.between(LocalDateTime.now(clock), expiration).toSeconds()
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is OAuth2AuthorizedRefreshToken && other.tokenId == this.tokenId -> true
        else -> false
    }

    override fun hashCode(): Int = tokenId.hashCode()
}