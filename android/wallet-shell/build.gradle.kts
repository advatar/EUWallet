plugins {
    id("com.android.library")
}

android {
    namespace = "eu.advatar.wallet.shell"
    compileSdk = 36

    defaultConfig {
        minSdk = 31
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.all {
            it.useJUnit()
        }
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        // Versions are deliberately pinned and compileSdk matches the checked-in build contract.
        // Availability checks are not code-quality findings and would make old commits non-reproducible.
        disable += setOf("GradleDependency", "NewerVersionAvailable")
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    implementation("com.governikus:ausweisapp:2.5.4")
    implementation("androidx.annotation:annotation:1.9.1")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation("junit:junit:4.13.2")
    // Android supplies org.json on-device; local JVM tests need its reference implementation.
    testImplementation("org.json:json:20260522")
}
