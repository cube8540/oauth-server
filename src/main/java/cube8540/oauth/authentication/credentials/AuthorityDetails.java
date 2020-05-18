package cube8540.oauth.authentication.credentials;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel(value = "권한 상세 정보")
public interface AuthorityDetails {

    @ApiModelProperty(value = "권한 코드", required = true, example = "AUTH_USER")
    String getCode();

    @ApiModelProperty(value = "권한 설명", required = true, example = "Default User Authority")
    String getDescription();

    @ApiModelProperty(value = "권한 타입", required = true, example = "AUTHORITY")
    AuthorityType getAuthorityType();

}
