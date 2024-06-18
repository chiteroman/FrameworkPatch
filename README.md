# Framework Patch
Modify framework.jar to build a valid certificate chain.

## Requirements
- Intermediate Windows and Linux knowledge.
- Intermediate Java and Smali knowledge.
- WSL (only in Windows).
- Java.
- 7zip.

In GNU/Linux distro, install these packages (I use Ubuntu in WSL2):
```
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y default-jdk zipalign
```

## WARNING
**This is for advanced users, if you don't know about programming either Linux, this is not for you...**

No support will be provided.

## How can I make my system rw?
If you don't know how to do that just use a module for Magisk, KernelSU or APatch.

Also, in modern devices, you must format data because modifying super partition breaks AVB.

## Tutorial
First, cd to a working (and clean) directory.

Pull framework.jar from your device:
```
adb pull /system/framework/framework.jar
```

Now, compile [smali](https://github.com/google/smali):
(Use WSL if you are in Windows)
```
git clone --depth=1 https://github.com/google/smali.git
cd smali
./gradlew build
```

Then pick smali and baksmali fatJars and paste to working dir.

Using 7zip, extract framework.jar to framework/ directory.

Now using [jadx](https://github.com/skylot/jadx), open framework.jar and check these classes:
- android.security.keystore2.AndroidKeyStoreSpi
- android.app.Instrumentation
- android.app.ApplicationPackageManager

You must check for the .dex they are in. You can know that by checking the text in the class declaration, something like this:
```
/* loaded from: classes3.dex */
public class AndroidKeyStoreSpi extends KeyStoreSpi

/* loaded from: classes.dex */
public class Instrumentation

/* loaded from: classes.dex */
public class ApplicationPackageManager extends PackageManager
````

Now using baksmali.jar, decompile all .dex files:
```
java -jar baksmali.jar d -a (ANDROID API LEVEL) framework/classes.dex -o classes
java -jar baksmali.jar d -a (ANDROID API LEVEL) framework/classes2.dex -o classes2
java -jar baksmali.jar d -a (ANDROID API LEVEL) framework/classes3.dex -o classes3
...
```

After all .dex files are decompiled, you must search in folders for these files and modify like this:

- AndroidKeyStoreSpi.smali:

Search for method "engineGetCertificateChain" and there should be a line near the end like this:
```
const/4 v4, 0x0
aput-object v2, v3, v4
return-object v3
```

In this example:

v2 -> leaf cert.
v3 -> certificate chain.
v4 -> 0, the position to insert the leaf cert in certificate chain.

It may be different in your .smali file. Do not copy and paste...

After aput operation, you must add this:
```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;
move-result-object XX
```

Replace XX with the leaf certificate register.

So the final code (in this example) should be this:
```
const/4 v4, 0x0
aput-object v2, v3, v4
invoke-static {v3}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;
move-result-object v3
return-object v3
```

- Instrumentation.smali:

Search for "newApplication" methods and before the return operation, add this:
```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->newApplication(Landroid/content/Context;)V
```

Replace XX with the Context register.

- ApplicationPackageManager.smali

Search for "hasSystemFeature" method:
```
.method public whitelist hasSystemFeature(Ljava/lang/String;)Z
    .registers 3
    .param p1, "name"    # Ljava/lang/String;

    .line 768
    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Landroid/app/ApplicationPackageManager;->hasSystemFeature(Ljava/lang/String;I)Z

    move-result p1

    return p1
.end method
```

And modify like this:
```
.method public whitelist hasSystemFeature(Ljava/lang/String;)Z
    .registers 3
    .param p1, "name"    # Ljava/lang/String;

    .line 768
    const/4 v0, 0x0

    invoke-virtual {p0, p1, v0}, Landroid/app/ApplicationPackageManager;->hasSystemFeature(Ljava/lang/String;I)Z

    move-result v0

    invoke-static {v0, p1}, Lcom/android/internal/util/framework/Android;->hasSystemFeature(ZLjava/lang/String;)Z

    move-result v0

    return v0
.end method
```

This hook is optional, but I recommend it if your device has Strongbox or app attest key support.

Now compile all dex:
```
java -jar smali.jar a -a (ANDROID API LEVEL) classes -o framework/classes.dex
java -jar smali.jar a -a (ANDROID API LEVEL) classes2 -o framework/classes2.dex
java -jar smali.jar a -a (ANDROID API LEVEL) classes3 -o framework/classes3.dex
...
```

Open this project in Android Studio and change EC and RSA keys, you must provide keybox private keys. Build project as release-build.

Using 7zip, extract classes.dex from the project release .apk file.

Rename extracted classes.dex to classesX.dex where X is (the number of .dex files in framework/ directory) + 1.

Copy renamed classesX.dex into framework/ directory.

Using 7zip, add all framework/ files to .zip archive **without** compression (Compression level: 0 - Store).

After you have the framework.zip, use zipalign:
```
zipalign -f -p -v -z 4 framework.zip framework.jar
```

Now move framework.jar to /system/framework, you can use a module to replace it or mount /system as read-write and replace it.

**Very important!** Remove all "boot-framework.*" files!

Lot of users need an extra step.

If Key Attestation show AOSP certificate and BL is locked but can't pass even the BASIC, try install [PIF fork](https://github.com/osm0sis/PlayIntegrityFork) in script-only-mode or [Shamiko](https://github.com/LSPosed/LSPosed.github.io/releases) (depends of Magisk variant) to spoof sensitive props.

Add Google Play Services/com.google.android.gms.unstable to DenyList/MagiskHide.
