package cube8540.oauth.authentication.credentials.role.application;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.RequiredArgsConstructor;
import lombok.Value;

import java.beans.ConstructorProperties;

@Value
@RequiredArgsConstructor(onConstructor_ = @ConstructorProperties(value = {"description", "basic"}))
@ApiModel(value = "권한 수정 정보")
public class RoleModifyRequest {

    @ApiModelProperty(value = "수정할 권한 설명", example = "Default User Role")
    String description;

    @ApiModelProperty(value = "기본 권한 여부", required = true, example = "false")
    boolean basic;

}
