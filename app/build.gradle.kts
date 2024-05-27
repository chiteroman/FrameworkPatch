plugins {
    id("com.android.application")
    id("org.lsposed.lsparanoid")
}

android {
    namespace = "com.android.internal.util.framework"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.android.internal.util.framework"
        minSdk = 28
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
    implementation("com.madgag.spongycastle:bcpkix-jdk15on:1.58.0.0")
}