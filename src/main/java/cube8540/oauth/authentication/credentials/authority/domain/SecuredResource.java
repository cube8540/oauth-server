package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.oauth.authentication.credentials.authority.domain.converter.ResourceConverter;
import cube8540.oauth.authentication.credentials.authority.error.ResourceInvalidException;
import cube8540.validator.core.Validator;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.data.domain.AbstractAggregateRoot;

import javax.persistence.AttributeOverride;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Table;
import java.net.URI;

@Getter
@ToString
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "secured_resource")
public class SecuredResource extends AbstractAggregateRoot<SecuredResource> {

    @EmbeddedId
    @AttributeOverride(name = "value", column = @Column(name = "resource_id", length = 32))
    private SecuredResourceId resourceId;

    @Convert(converter = ResourceConverter.class)
    @Column(name = "resource", length = 128, nullable = false)
    private URI resource;

    @Enumerated(EnumType.STRING)
    @Column(name = "method", length = 32, nullable = false)
    private ResourceMethod method;

    public void changeResourceInfo(URI changeResource, ResourceMethod changeMethod) {
        this.resource = changeResource;
        this.method = changeMethod;

        // TODO 이벤트를 리스닝하여 스프링 시큐리티의 권한 정보를 리로딩 하기
        registerEvent(new SecuredResourceChangedEvent(resourceId));
    }

    public void validation(SecuredResourceValidationPolicy policy) {
        Validator.of(this).registerRule(policy.resourceIdRule())
                .registerRule(policy.resourceRule())
                .registerRule(policy.methodRule())
                .getResult().hasErrorThrows(ResourceInvalidException::instance);
    }
}
