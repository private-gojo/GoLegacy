val releaseVersionName = "0.1.0"

plugins {
    id("com.android.application")
}

android {
    namespace = "dev.go.core"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "dev.go.core"
        minSdk = 21
        targetSdk = 37
        versionCode = 1
        versionName = releaseVersionName
    }

    signingConfigs {
        val storePath = System.getenv("GO_KEYSTORE_PATH")
        if (!storePath.isNullOrBlank()) {
            create("release") {
                storeFile = file(storePath)
                storePassword = System.getenv("GO_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("GO_KEY_ALIAS")
                keyPassword = System.getenv("GO_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug { applicationIdSuffix = ".debug" }
        release {
            isMinifyEnabled = true
            if (!System.getenv("GO_KEYSTORE_PATH").isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(files("libs/go-core.aar"))
    implementation(files("libs/hev-socks5-tunnel.aar"))
}

tasks.register<Copy>("copyGoReleaseApk") {
    dependsOn("assembleRelease")
    from(fileTree(layout.buildDirectory.dir("outputs/apk/release")) { include("*.apk") })
    into(layout.buildDirectory.dir("outputs/go"))
    rename { "Go-$releaseVersionName.apk" }
}
