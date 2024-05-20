plugins {
    id("com.android.application")
    id("org.lsposed.lsparanoid")
}

android {
    namespace = "com.android.internal.util.framework"
    compileSdk = 34

    packaging {
        resources {
            excludes += "META-INF/**"
        }
    }

    defaultConfig {
        applicationId = "com.android.internal.util.framework"
        minSdk = 34
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        multiDexEnabled = false
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            multiDexEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}