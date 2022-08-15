pipeline {
    agent any
    stages {
        stage('Setup profile') {
            steps {
                sh 'cp ${CONFIG_LOCATION}/application-${ACTIVE_PROFILE}.yml ./src/main/resources/application.yml'
                sh 'cp ${CONFIG_LOCATION}/logback-${ACTIVE_PROFILE}.xml ./src/main/resources/logback.xml'
            }
        }
        stage('Gradle build') {
            steps {
                sh 'gradle clean bootJar --stacktrace --debug --scan'
                script {
                    buildVersion = sh(script: 'gradle -q printVersion', returnStdout: true)
                }
            }
        }
        stage('Docker build') {
            steps {
                script {
                    echo "buildVersion=${buildVersion}"
                    app = docker.build("oauth-server:${buildVersion}", "-t oauth-server:latest --build-arg V_VERSION=${buildVersion} --build-arg V_PROFILE=$ACTIVE_PROFILE .")
                }
            }
        }
    }
}