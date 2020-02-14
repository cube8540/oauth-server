package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.authority.domain.AuthorityCode;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.AttributeOverride;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

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

    @ElementCollection
    @CollectionTable(name = "oauth2_scope_accessible_authority", joinColumns = @JoinColumn(name = "scope_id", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "authority", length = 32, nullable = false))
    private Set<AuthorityCode> accessibleAuthority;

    public OAuth2Scope(String scopeId, String description) {
        this.id = new OAuth2ScopeId(scopeId);
        this.description = description;
    }

    public void addAccessibleAuthority(AuthorityCode authority) {
        if (this.accessibleAuthority == null) {
            this.accessibleAuthority = new HashSet<>();
        }
        this.accessibleAuthority.add(authority);
    }

    public void removeAccessibleAuthority(AuthorityCode code) {
        if (this.accessibleAuthority != null) {
            this.accessibleAuthority.remove(code);
        }
    }

    public boolean isAccessible(Authentication authentication) {
        if (this.accessibleAuthority == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).map(AuthorityCode::new)
                .anyMatch(authority -> accessibleAuthority.contains(authority));
    }
}
