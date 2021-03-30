package cube8540.oauth.authentication.oauth.token.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.converter.AuthorizationGrantTypeConverter
import org.hibernate.annotations.DynamicInsert
import org.hibernate.annotations.DynamicUpdate
import org.hibernate.annotations.Fetch
import org.hibernate.annotations.FetchMode
import org.springframework.data.domain.AbstractAggregateRoot
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.time.Clock
import java.time.Duration
import java.time.LocalDateTime
import java.util.*
import javax.persistence.AttributeOverride
import javax.persistence.CascadeType
import javax.persistence.CollectionTable
import javax.persistence.Column
import javax.persistence.Convert
import javax.persistence.ElementCollection
import javax.persistence.Embedded
import javax.persistence.EmbeddedId
import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.JoinColumn
import javax.persistence.JoinTable
import javax.persistence.MapKeyColumn
import javax.persistence.OneToOne
import javax.persistence.Table
import javax.persistence.Transient
import javax.persistence.UniqueConstraint

@Entity
@Table(name = "oauth2_access_token", uniqueConstraints = [
    UniqueConstraint(name = "access_token_unique_key", columnNames = ["compose_unique_key"])
])
@DynamicInsert
@DynamicUpdate
class OAuth2AuthorizedAccessToken(

    @Transient
    private val tokenIdGenerator: OAuth2TokenIdGenerator,

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "username", length = 32))
    var username: PrincipalUsername?,

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "client_id", length = 32, nullable = false))
    var client: OAuth2ClientId,

    @ElementCollection
    @Fetch(FetchMode.JOIN)
    @CollectionTable(name = "oauth2_token_scope", joinColumns = [JoinColumn(name = "token_id", nullable = false)])
    @AttributeOverride(name = "value", column = Column(name = "scope_id", length = 32, nullable = false))
    var scopes: MutableSet<AuthorityCode>,

    @Column(name = "expiration", nullable = false)
    var expiration: LocalDateTime,

    @Column(name = "grant_type", nullable = false, length = 32)
    @Convert(converter = AuthorizationGrantTypeConverter::class)
    var tokenGrantType: AuthorizationGrantType,

    @Column(name = "issued_at", nullable = false)
    var issuedAt: LocalDateTime

): AbstractAggregateRoot<OAuth2AuthorizedAccessToken>() {

    companion object {
        @JvmStatic
        @Transient
        internal var clock: Clock = AuthenticationApplication.DEFAULT_CLOCK
    }

    @EmbeddedId
    @AttributeOverride(name = "value", column = Column(name = "token_id", length = 32))
    var tokenId: OAuth2TokenId = tokenIdGenerator.generateTokenValue()

    @Embedded
    @AttributeOverride(name = "value", column = Column(name = "compose_unique_key", length = 32, nullable = false))
    var composeUniqueKey: OAuth2ComposeUniqueKey? = null

    @Fetch(FetchMode.JOIN)
    @JoinColumn(name = "access_token_id")
    @OneToOne(cascade = [CascadeType.ALL], fetch = FetchType.EAGER, mappedBy = "accessToken")
    var refreshToken: OAuth2AuthorizedRefreshToken? = null

    @ElementCollection
    @Fetch(FetchMode.JOIN)
    @JoinTable(name = "oauth2_access_token_additional_information", joinColumns = [JoinColumn(name = "token_id")])
    @MapKeyColumn(name = "info_key")
    @Column(name = "info_value", length = 128)
    var additionalInformation: MutableMap<String, String?>? = null

    fun isExpired() = expiration.isBefore(LocalDateTime.now(clock))

    fun expiresIn(): Long {
        if (isExpired()) {
            return 0.toLong()
        }
        return Duration.between(LocalDateTime.now(clock), expiration).toSeconds()
    }

    fun putAdditionalInformation(key: String, value: String) {
        if (this.additionalInformation == null) {
            this.additionalInformation = HashMap()
        }
        this.additionalInformation!![key] = value
    }

    fun generateRefreshToken(refreshTokenIdGenerator: OAuth2TokenIdGenerator, expirationDateTime: LocalDateTime) {
        this.refreshToken = OAuth2AuthorizedRefreshToken(refreshTokenIdGenerator, expirationDateTime, this)
    }

    fun generateComposeUniqueKey(generator: OAuth2ComposeUniqueKeyGenerator) {
        this.composeUniqueKey = generator.generateKey(this)
    }

    override fun equals(other: Any?): Boolean = when {
        other == null -> false
        other is OAuth2AuthorizedAccessToken && other.tokenId == this.tokenId -> true
        else -> false
    }

    override fun hashCode(): Int = tokenId.hashCode()
}