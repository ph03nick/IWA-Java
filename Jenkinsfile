pipeline {
    agent any
    triggers {
        githubPush()
    }
    stages {
        stage('Hello') {
            steps {
                git branch: 'main', url: 'https://github.com/ph03nick/IWA-Java.git'
            }
        }
    }
}
