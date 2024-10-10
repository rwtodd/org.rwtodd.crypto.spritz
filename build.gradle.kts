subprojects {
    version = "1.0.0"
    group = "org.rwtodd"

    repositories {
        mavenCentral()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.release = 21
    }

    tasks.withType<Test>().configureEach {
        testLogging {
            events("skipped", "failed")
        }
    }
}
