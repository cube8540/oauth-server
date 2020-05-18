package cube8540.oauth.authentication.credentials;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.MappedSuperclass;

@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@MappedSuperclass
public class AbstractAuthority extends AbstractAggregateRoot<AbstractAuthority> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "code", length = 32))
    private AuthorityCode code;

    @Setter
    @Column(name = "description", length = 32)
    private String description;

}
