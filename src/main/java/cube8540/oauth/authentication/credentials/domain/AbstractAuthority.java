package cube8540.oauth.authentication.credentials.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "authority")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name = "type")
public class AbstractAuthority extends AbstractAggregateRoot<AbstractAuthority> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "code", length = 32))
    private AuthorityCode code;

    @Setter
    @Column(name = "description", length = 32)
    private String description;

}
