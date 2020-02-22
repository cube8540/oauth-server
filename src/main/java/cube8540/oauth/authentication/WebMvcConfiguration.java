package cube8540.oauth.authentication;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import com.navercorp.lucy.security.xss.servletfilter.XssEscapeServletFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

@Configuration
public class WebMvcConfiguration implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/accounts/signin").setViewName("accounts/signin");
        registry.addViewController("/oauth/approval").setViewName("oauth/approval");
    }

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.removeIf(converter -> converter instanceof MappingJackson2HttpMessageConverter);
        converters.add(new MappingJackson2HttpMessageConverter(escapeObjectMapper()));
    }

    @Bean
    public FilterRegistrationBean<Filter> xssEscapeServletFilter() {
        FilterRegistrationBean<Filter> filterBean = new FilterRegistrationBean<>(new XssEscapeServletFilter());

        filterBean.setUrlPatterns(Collections.singletonList("/*"));
        return filterBean;
    }

    @Bean
    @Primary
    public ObjectMapper escapeObjectMapper() {
        Module timeModule = new JavaTimeModule()
                .addDeserializer(LocalDateTime.class, LocalDateTimeDeserializer.INSTANCE)
                .addSerializer(LocalDateTime.class, LocalDateTimeSerializer.INSTANCE);

        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(timeModule)
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        objectMapper.getFactory().setCharacterEscapes(new HtmlCharacterEscapes());
        return objectMapper;
    }
}
