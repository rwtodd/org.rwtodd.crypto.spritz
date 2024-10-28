plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    `jvm-test-suite`

    // upload to Maven
    `maven-publish`
    signing
}

apply(from = rootProject.file("buildSrc/shared.gradle.kts"))

base {
  archivesName = "org.rwtodd.crypto.spritz"
}

sourceSets {
    main { 
        java { setSrcDirs(listOf("src")) }
    }
}

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
            sources {
                java { setSrcDirs(listOf("testsrc")) }
            }
        }
    }
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "org.rwtodd.crypto.spritz"
            from(components["java"])
            pom {
                name = "org.rwtodd.crypto.spritz"
                description = "A spritz cipher library."
                url = "https://github.com/rwtodd/org.rwtodd.crypto.spritz"
                //properties = mapOf( "" to "" )
                licenses {
                    license {
                        name = "MIT License"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                developers {
                    developer {
                        id = "rwtodd"
                        name = "Richard Todd"
                        email = "rwtodd@users.noreply.github.com"
                    }
                }
                scm {
                    connection = "scm:git:https://github.com/rwtodd/org.rwtodd.crypto.spritz.git"
                    developerConnection = "scm:git:https://github.com/rwtodd/org.rwtodd.crypto.spritz.git"
                    url = "https://github.com/rwtodd/org.rwtodd.crypto.spritz"
                }
            }
        }
    }
    repositories {
        maven {
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2")
            credentials {
                username = project.findProperty("ossrhUsername") as String? ?: ""
                password = project.findProperty("ossrhPassword") as String? ?: ""
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}
