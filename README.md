# Uonet+ request signer for android

[![Bintray](https://img.shields.io/bintray/v/wulkanowy/wulkanowy/signer-android.svg?style=flat-square)](https://bintray.com/wulkanowy/wulkanowy/signer-android)

## Instalation

```grovy
allprojects {
    repositories {
        maven { url "https://dl.bintray.com/wulkanowy/wulkanowy" }
    }
}

dependencies {
    implementation "io.github.wulkanowy:signer-android:0.1.1"
}
```

## Usage

```kotlin
import io.github.wulkanowy.signer.android.signContent
import io.github.wulkanowy.signer.android.getPrivateKeyFromCert

// sign content using PFX certificate and API password
val signed = signContent(password, certificate, content)

// sign content using private key extracted from PFX
val signed = signContent(key, content)

// extract private key from PFX
// using a once generated private key is about 250x faster
// than using the PFX each time
val privateKey = getPrivateKeyFromCert(password, certificate)
```

## Tests

```bash
$ ./gradlew test
```
