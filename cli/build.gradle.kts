plugins {
    java
    application
}

apply(from = rootProject.file("buildSrc/shared.gradle.kts"))

sourceSets {
    main { 
        java { setSrcDirs(listOf("src")) }
    }
}


base {
    archivesName = "spritz-cli"
}

dependencies {
    implementation(project(":lib"))
    implementation("org.rwtodd:org.rwtodd.args:2.0.1")
}

application {
    applicationName = "spritz"
    mainModule = "spritzcli"
    mainClass = "rwt.Cmd"
}
