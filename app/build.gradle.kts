plugins {
    id("com.android.application")
}

android {
    namespace = "es.chiteroman.framework"
    compileSdk = 34

    defaultConfig {
        applicationId = "es.chiteroman.framework"
        minSdk = 32
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
    implementation("org.bouncycastle:bcpkix-jdk18on:1.77")
}