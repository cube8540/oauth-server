package cube8540.oauth.authentication.credentials.resource.domain;

import lombok.Value;

@Value
public class SecuredResourceChangedEvent {

    private SecuredResourceId resourceId;

}
