package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "oauth2_scope")
public class OAuth2Scope extends AbstractAggregateRoot<OAuth2Scope> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "scope_id", length = 32))
    private OAuth2ScopeId id;

    @Column(name = "description", length = 64)
    private String description;

    public OAuth2Scope(String scopeId, String description) {
        this.id = new OAuth2ScopeId(scopeId);
        this.description = description;
    }
}
