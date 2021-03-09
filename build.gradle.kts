import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    val kotlinVersion = "1.4.21"

    id("org.springframework.boot") version "2.2.2.RELEASE"
    id("io.spring.dependency-management") version "1.0.8.RELEASE"

    kotlin("jvm") version kotlinVersion
    kotlin("kapt") version kotlinVersion
    kotlin("plugin.spring") version kotlinVersion
    kotlin("plugin.jpa") version kotlinVersion
    kotlin("plugin.allopen") version kotlinVersion

    id("org.sonarqube") version "2.7"
    id("jacoco")
}

allOpen {
    annotation("javax.persistence.Entity")
    annotation("javax.persistence.MappedSuperclass")
    annotation("javax.persistence.Embeddable")
}

jacoco {
    toolVersion = "0.8.5"
}

group = "cube8540.oauth"
version = "2.8.0.HOTFIX"

configurations {
    compileOnly {
        extendsFrom(configurations.annotationProcessor.get())
    }
}

repositories {
    mavenCentral()
    jcenter()
}

sonarqube {
    properties {
        property("sonarqube.sourceEncoding", "UTF-8")
        property("sonarqube.source", "src")
        property("sonarqube.language", "java")
        property("sonar.jacoco.reportPaths", "build/jacoco/jacoco.exec")
    }
}

tasks.withType<JacocoReport> {
    reports {
        xml.isEnabled = true
        csv.isEnabled = false
        html.destination = file("${buildDir}/jacocoHtml")
    }

    finalizedBy("jacocoTestCoverageVerification")
}

tasks.withType<Test> {
    extensions.configure(JacocoTaskExtension::class) {
        setDestinationFile(file("${buildDir}/jacoco/jacoco.exec"))
    }

    useJUnitPlatform()
    finalizedBy("jacocoTestReport")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict", "-Xjvm-default=all")
        jvmTarget = "11"
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlin:kotlin-noarg")

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-devtools")
    implementation("org.springframework.boot:spring-boot-starter-security")

    implementation("org.springframework.retry:spring-retry")
    implementation("org.springframework.security:spring-security-oauth2-resource-server:5.2.1.RELEASE")

    implementation("com.nimbusds:oauth2-oidc-sdk:8.3")

    implementation("io.springfox:springfox-swagger2:2.9.2")
    implementation("io.springfox:springfox-swagger-ui:2.9.2")

    implementation("com.h2database:h2:1.4.200")
    implementation("org.mariadb.jdbc:mariadb-java-client:2.5.2")

    implementation("com.navercorp.lucy:lucy-xss:1.6.3")
    implementation("com.navercorp.lucy:lucy-xss-servlet:2.0.1")

    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")

    implementation("org.apache.commons:commons-text:1.8")
    implementation("cube8540.validator:validator-core:1.1.1")

    implementation("org.mockito:mockito-inline:2.21.0")

    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
    }
}
