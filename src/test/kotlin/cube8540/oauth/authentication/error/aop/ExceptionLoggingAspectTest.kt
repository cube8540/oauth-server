package cube8540.oauth.authentication.error.aop

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.aspectj.lang.ProceedingJoinPoint
import org.junit.jupiter.api.Test

class ExceptionLoggingAspectTest {

    private val loggingAspect = ExceptionLoggingAspect()

    @Test
    fun `call join point proceed`() {
        val joinPoint: ProceedingJoinPoint = mockk(relaxed = true)

        every { joinPoint.args } returns emptyArray()

        loggingAspect.loggingException(joinPoint)
        verify { joinPoint.proceed() }
    }
}