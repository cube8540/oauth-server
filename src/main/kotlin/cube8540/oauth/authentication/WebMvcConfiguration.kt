package cube8540.oauth.authentication

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.Module
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer
import com.navercorp.lucy.security.xss.servletfilter.XssEscapeServletFilter
import cube8540.oauth.authentication.credentials.oauth.converter.OAuth2AccessTokenDetailsSerializer
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ErrorSerializer
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Primary
import org.springframework.http.converter.HttpMessageConverter
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.servlet.Filter

@Configuration
class WebMvcConfiguration: WebMvcConfigurer {

    override fun addViewControllers(registry: ViewControllerRegistry) {
        registry.addViewController("/accounts/signin").setViewName("accounts/signin")
        registry.addViewController("/oauth/approval").setViewName("oauth/approval")
    }

    override fun addResourceHandlers(registry: ResourceHandlerRegistry) {
        // swagger ui
        registry.addResourceHandler("swagger-ui.html")
            .addResourceLocations("classpath:/META-INF/resources/")
        registry.addResourceHandler("/webjars/**")
            .addResourceLocations("classpath:/META-INF/resources/webjars/")
    }

    override fun configureMessageConverters(converters: MutableList<HttpMessageConverter<*>>) {
        converters.removeIf { converter: HttpMessageConverter<*> -> converter is MappingJackson2HttpMessageConverter }
        converters.add(MappingJackson2HttpMessageConverter(escapeObjectMapper()!!))
    }

    @Bean
    @Primary
    fun escapeObjectMapper(): ObjectMapper? {
        val timeModule: Module = JavaTimeModule()
            .addDeserializer(LocalDateTime::class.java, LocalDateTimeDeserializer(DateTimeFormatter.ISO_LOCAL_DATE_TIME))
            .addSerializer(LocalDateTime::class.java, LocalDateTimeSerializer(DateTimeFormatter.ISO_LOCAL_DATE_TIME))

        val oauth2Module: Module = SimpleModule()
            .addSerializer(OAuth2Error::class.java, OAuth2ErrorSerializer())
            .addSerializer(OAuth2AccessTokenDetails::class.java, OAuth2AccessTokenDetailsSerializer())

        val objectMapper = ObjectMapper()
            .registerModule(timeModule)
            .registerModule(oauth2Module)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)

        objectMapper.factory.characterEscapes = HtmlCharacterEscapes()
        return objectMapper
    }

    @Bean
    fun xssEscapeServletFilter(): FilterRegistrationBean<Filter>? {
        val filterBean = FilterRegistrationBean<Filter>(XssEscapeServletFilter())
        filterBean.urlPatterns = listOf("/*")
        return filterBean
    }

    @Bean
    @Primary
    fun passwordEncoder(): PasswordEncoder? {
        return BCryptPasswordEncoder()
    }
}