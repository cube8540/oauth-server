package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties(value = {"authority", "authorityType"}))
@ApiModel(value = "접근 권한")
public class AccessibleAuthorityValue {

    @ApiModelProperty(value = "접근 권한 코드", required = true, example = "ROEL_USER")
    String authority;

    public static AccessibleAuthorityValue of(AccessibleAuthority authority) {
        return new AccessibleAuthorityValue(authority.getAuthority());
    }

}
