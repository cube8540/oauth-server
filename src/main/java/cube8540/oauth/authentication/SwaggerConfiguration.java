package cube8540.oauth.authentication;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.security.Principal;

@Configuration
@EnableSwagger2
public class SwaggerConfiguration {

    private static final String VERSION = "2.0.0";

    @Bean
    public Docket accountsAPI() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .ignoredParameterTypes(Authentication.class)
                .ignoredParameterTypes(Principal.class)
                .select()
                .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.users.endpoint"))
                .paths(PathSelectors.ant("/api/accounts/**"))
                .build()
                .groupName("Accounts API")
                .apiInfo(createApiInfo("계정 API"));
    }

    @Bean
    public Docket oauth2ClientAPI() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .ignoredParameterTypes(Authentication.class)
                .ignoredParameterTypes(Principal.class)
                .select()
                .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.credentials.oauth.client.endpoint"))
                .paths(PathSelectors.ant("/api/clients/**"))
                .build()
                .groupName("OAuth2 Client API")
                .apiInfo(createApiInfo("OAuth2 클라이언트 API"));
    }

    @Bean
    public Docket oauth2TokenAPI() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .ignoredParameterTypes(Authentication.class)
                .ignoredParameterTypes(Principal.class)
                .select()
                .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.credentials.oauth.token.endpoint"))
                .paths(PathSelectors.ant("/api/tokens/**"))
                .build()
                .groupName("OAuth2 Token API")
                .apiInfo(createApiInfo("OAuth2 토큰 API"));
    }

    @Bean
    public Docket oauth2ScopeAPI() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .ignoredParameterTypes(Authentication.class)
                .ignoredParameterTypes(Principal.class)
                .select()
                .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.credentials.oauth.scope.endpoint"))
                .paths(PathSelectors.ant("/api/scopes/**"))
                .build()
                .groupName("OAuth2 Scope API")
                .apiInfo(createApiInfo("OAuth2 스코프 API"));
    }

    @Bean
    public Docket securedResourceAPI() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(false)
                .ignoredParameterTypes(Authentication.class)
                .ignoredParameterTypes(Principal.class)
                .select()
                .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.credentials.resource.endpoint"))
                .paths(PathSelectors.ant("/api/secured-resources/**"))
                .build()
                .groupName("Secured Resource API")
                .apiInfo(createApiInfo("보호 자원 API"));
    }

    private ApiInfo createApiInfo(String title) {
        return new ApiInfoBuilder()
                .title(title)
                .version(SwaggerConfiguration.VERSION)
                .build();
    }
}
