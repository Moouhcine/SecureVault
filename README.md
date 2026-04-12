# SecureVault

SecureVault is an Android app focused on secure, offline storage of credentials and documents.

## Build (Release, Signed)
1. Android Studio: Build > Generate Signed App Bundle or APK... > APK
2. Choose your `.jks` keystore and select `release`
3. Output APK: `app/build/outputs/apk/release/app-release.apk`

## Features
- Strong biometric gate
- EncryptedSharedPreferences for credentials
- EncryptedFile for documents
- Autofill service with biometric auth
- Offline-only (no network permissions)

## Notes
- For debugging, RASP checks may be bypassed. Re-enable strict mode before delivery.

