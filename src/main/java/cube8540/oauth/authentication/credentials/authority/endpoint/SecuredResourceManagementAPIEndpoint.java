package cube8540.oauth.authentication.credentials.authority.endpoint;

import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceDetails;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceManagementService;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceModifyRequest;
import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceRegisterRequest;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class SecuredResourceManagementAPIEndpoint {

    private final SecuredResourceManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("securedResourceExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public SecuredResourceManagementAPIEndpoint(SecuredResourceManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/secured-resources/attributes/resource-id")
    public Map<String, Long> countResourceId(@RequestParam String resourceId) {
        long count = service.count(resourceId);
        return Collections.singletonMap("count", count);
    }

    @GetMapping(value = "/api/secured-resources")
    public Map<String, List<SecuredResourceDetails>> getResources() {
        List<SecuredResourceDetails> resources = service.getResources();
        return Collections.singletonMap("resources", resources);
    }

    @PostMapping(value = "/api/secured-resources")
    public SecuredResourceDetails registerNewResource(@RequestBody SecuredResourceRegisterRequest registerRequest) {
        return service.registerNewResource(registerRequest);
    }

    @PutMapping(value = "/api/secured-resources/{resourceId}")
    public SecuredResourceDetails modifyResource(@PathVariable("resourceId") String resourceId, @RequestBody SecuredResourceModifyRequest modifyRequest) {
        return service.modifyResource(resourceId, modifyRequest);
    }

    @DeleteMapping(value = "/api/secured-resources/{resourceId}")
    public SecuredResourceDetails removeResource(@PathVariable("resourceId") String resourceId) {
        return service.removeResource(resourceId);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
