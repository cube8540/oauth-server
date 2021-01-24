package cube8540.oauth.authentication

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.core.Authentication
import springfox.documentation.builders.ApiInfoBuilder
import springfox.documentation.builders.PathSelectors
import springfox.documentation.builders.RequestHandlerSelectors
import springfox.documentation.service.ApiInfo
import springfox.documentation.spi.DocumentationType
import springfox.documentation.spring.web.plugins.Docket
import springfox.documentation.swagger2.annotations.EnableSwagger2
import java.security.Principal


private const val version = "2.0.0"

@Configuration
@EnableSwagger2
@Profile(value = ["local"])
class SwaggerConfiguration {

    @Bean
    fun accountsAPI(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
            .useDefaultResponseMessages(false)
            .ignoredParameterTypes(Authentication::class.java)
            .ignoredParameterTypes(Principal::class.java)
            .select()
            .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.users.endpoint"))
            .paths(PathSelectors.ant("/api/accounts/**"))
            .build()
            .groupName("Accounts API")
            .apiInfo(createApiInfo("계정 API"))
    }

    @Bean
    fun oauth2ClientAPI(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
            .useDefaultResponseMessages(false)
            .ignoredParameterTypes(Authentication::class.java)
            .ignoredParameterTypes(Principal::class.java)
            .select()
            .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.oauth.client.endpoint"))
            .paths(PathSelectors.ant("/api/clients/**"))
            .build()
            .groupName("OAuth2 Client API")
            .apiInfo(createApiInfo("OAuth2 클라이언트 API"))
    }

    @Bean
    fun oauth2TokenAPI(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
            .useDefaultResponseMessages(false)
            .ignoredParameterTypes(Authentication::class.java)
            .ignoredParameterTypes(Principal::class.java)
            .select()
            .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.oauth.token.endpoint"))
            .paths(PathSelectors.ant("/api/tokens/**"))
            .build()
            .groupName("OAuth2 Token API")
            .apiInfo(createApiInfo("OAuth2 토큰 API"))
    }

    @Bean
    fun oauth2ScopeAPI(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
            .useDefaultResponseMessages(false)
            .ignoredParameterTypes(Authentication::class.java)
            .ignoredParameterTypes(Principal::class.java)
            .select()
            .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.oauth.scope.endpoint"))
            .paths(PathSelectors.ant("/api/scopes/**"))
            .build()
            .groupName("OAuth2 Scope API")
            .apiInfo(createApiInfo("OAuth2 스코프 API"))
    }

    @Bean
    fun securedResourceAPI(): Docket {
        return Docket(DocumentationType.SWAGGER_2)
            .useDefaultResponseMessages(false)
            .ignoredParameterTypes(Authentication::class.java)
            .ignoredParameterTypes(Principal::class.java)
            .select()
            .apis(RequestHandlerSelectors.basePackage("cube8540.oauth.authentication.resource.endpoint"))
            .paths(PathSelectors.ant("/api/secured-resources/**"))
            .build()
            .groupName("Secured Resource API")
            .apiInfo(createApiInfo("보호 자원 API"))
    }

    private fun createApiInfo(title: String): ApiInfo = ApiInfoBuilder().title(title).version(version).build()
}