import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// SecureCode Android client SDK — ZERO external dependencies by design:
// every primitive (Base32, canonical JSON, Ed25519 verify, HKDF, AES) is
// either implemented in-tree or comes from the platform.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.securecode.protection"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

// The conformance suite resolves sdks/vectors.json from the repo checkout
// (see VectorConformanceTest) and writes build/securecode-selftest.json —
// validate that report with:
//   python -m tests.cross_platform_vectors --check <report>

dependencies {
    testImplementation("junit:junit:4.13.2")
}
