import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("software.amazon.cryptools:AmazonCorrettoCryptoProvider:2.2.0:linux-x86_64")
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.add("--enable-preview")
}

tasks.withType<JavaExec>().configureEach {
    jvmArgs("--enable-preview")
}

tasks.withType<ShadowJar> {
    manifest {
        attributes["Main-Class"] = "solver.Main"
    }
}

tasks {
    build {
        dependsOn(shadowJar)
    }
}
