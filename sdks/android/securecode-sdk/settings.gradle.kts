// Standalone checkout for running the conformance suite:
//     cd sdks/android/securecode-sdk && gradle test
// In an app you instead add this module directly:
//     settings.gradle.kts:  include(":securecode-sdk")
//                           project(":securecode-sdk").projectDir =
//                               file("path/to/sdks/android/securecode-sdk")
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.library") version "8.7.3"
        id("org.jetbrains.kotlin.android") version "2.0.21"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "securecode-sdk"
