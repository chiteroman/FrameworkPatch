# Framework Patch
Modify framework.jar to build a valid certificate chain.

## Requirements
- Intermediate Windows and Linux knowledge.
- Intermediate Java and Smali knowledge.
- WSL (only in Windows).
- Java.
- 7zip.

In GNU/Linux distro, install this packages (I use Ubuntu in WSL2):
```
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y default-jdk zipalign
```

## First steps
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

Using 7zip extract framework.jar to framework/ directory.

Now using [jadx](https://github.com/skylot/jadx) open framework.jar and check these classes:
- android.security.keystore2.AndroidKeyStoreSpi
- android.app.Instrumentation

You must check in where .dex they are, you can know by checking upper text in class declaration, something like this:
```
/* loaded from: classes3.dex */
public class AndroidKeyStoreSpi extends KeyStoreSpi

/* loaded from: classes.dex */
public class Instrumentation 
````

Now using baksmali.jar, decompile that .dex files:
```
java -jar baksmali.jar d framework/classes3.dex -o classes3
java -jar baksmali.jar d framework/classes.dex -o classes
```

In progress...