package cube8540.oauth.authentication

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor
import java.util.concurrent.Executor

@EnableAsync
@Configuration
class SpringAsyncThreadConfiguration {

    @Bean("asyncThreadPoolTaskExecutor")
    fun asyncThreadPoolTaskExecutor(): Executor {
        val executor = ThreadPoolTaskExecutor()

        executor.corePoolSize = 4
        executor.maxPoolSize = 10
        executor.setQueueCapacity(10)
        executor.setThreadNamePrefix("Spring-Async-")
        executor.initialize()

        return executor
    }
}