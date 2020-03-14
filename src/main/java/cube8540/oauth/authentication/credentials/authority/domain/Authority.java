package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.oauth.authentication.credentials.authority.domain.exception.AuthorityInvalidException;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.CollectionTable;
import javax.persistence.Column;
import javax.persistence.ElementCollection;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.Table;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "authority")
public class Authority extends AbstractAggregateRoot<Authority> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "code", length = 32))
    private AuthorityCode code;

    @Setter
    @Column(name = "description", length = 64)
    private String description;

    @Column(name = "is_basic", nullable = false)
    private boolean basic;

    @ElementCollection
    @CollectionTable(name = "authority_accessible_resources", joinColumns = @JoinColumn(name = "authority", nullable = false))
    @AttributeOverride(name = "value", column = @Column(name = "resource_id", length = 128, nullable = false))
    private Set<SecuredResourceId> accessibleResources;

    public Authority(String code, String description) {
        this.code = new AuthorityCode(code);
        this.description = description;
        this.basic = false;
    }

    public void settingBasicAuthority() {
        this.basic = true;
    }

    public void settingNotBasicAuthority() {
        this.basic = false;
    }

    public void addAccessibleResource(SecuredResourceId securedResource) {
        if (this.accessibleResources == null) {
            this.accessibleResources = new HashSet<>();
        }
        this.accessibleResources.add(securedResource);

        registerAccessibleResourceChangedEvent();
    }

    public void removeAccessibleResource(SecuredResourceId securedResource) {
        Optional.ofNullable(this.accessibleResources).ifPresent(resources -> resources.remove(securedResource));

        registerAccessibleResourceChangedEvent();
    }

    public void validation(AuthorityValidationPolicy policy) {
        Validator.of(this).registerRule(policy.codeRule())
                .registerRule(policy.accessibleResourceRule())
                .getResult().hasErrorThrows(AuthorityInvalidException::instance);
    }

    private void registerAccessibleResourceChangedEvent() {
        AuthorityAccessibleResourceChangedEvent event = new AuthorityAccessibleResourceChangedEvent(code);
        if (!domainEvents().contains(event)) {
            registerEvent(event);
        }
    }
}
