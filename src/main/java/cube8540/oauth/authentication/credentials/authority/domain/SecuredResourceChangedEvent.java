package cube8540.oauth.authentication.credentials.authority.domain;

import lombok.Value;

@Value
public class SecuredResourceChangedEvent {

    private SecuredResourceId resourceId;

}
