package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.exception.ScopeInvalidException;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
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

    @Setter
    @Column(name = "description", length = 64)
    private String description;

    @ElementCollection
    @CollectionTable(name = "oauth2_scope_accessible_authority", joinColumns = @JoinColumn(name = "scope_id", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "authority", length = 32, nullable = false))
    private Set<OAuth2ScopeId> accessibleAuthority;

    public OAuth2Scope(String scopeId, String description) {
        this.id = new OAuth2ScopeId(scopeId);
        this.description = description;
    }

    public void addAccessibleAuthority(OAuth2ScopeId scope) {
        if (this.accessibleAuthority == null) {
            this.accessibleAuthority = new HashSet<>();
        }
        this.accessibleAuthority.add(scope);
    }

    public void removeAccessibleAuthority(OAuth2ScopeId scope) {
        if (this.accessibleAuthority != null) {
            this.accessibleAuthority.remove(scope);
        }
    }

    public boolean isAccessible(Authentication authentication) {
        if (this.accessibleAuthority == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).map(OAuth2ScopeId::new)
                .anyMatch(authority -> accessibleAuthority.contains(authority));
    }

    public void validate(OAuth2ScopeValidationPolicy policy) {
        Validator.of(this).registerRule(policy.scopeIdRule())
                .registerRule(policy.accessibleRule())
                .getResult().hasErrorThrows(ScopeInvalidException::instance);
    }
}
