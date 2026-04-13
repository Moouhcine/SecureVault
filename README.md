# SecureVault 🛡️

SecureVault est une application Android de haute sécurité conçue pour le stockage hors ligne de vos identifiants et informations sensibles. Grâce à une architecture "paranoid-by-design", elle garantit que vos données restent confidentielles et protégées contre les menaces les plus avancées.

## 🚀 Fonctionnalités Clés

- **Authentification Biométrique :** Accès verrouillé par empreinte digitale ou reconnaissance faciale obligatoire pour ouvrir le coffre.
- **Coffre-fort Chiffré :** Utilisation du standard AES-256 (GCM/SIV) pour protéger chaque donnée stockée.
- **Protection Anti-Capture :** Bloque automatiquement les captures d'écran et les enregistrements vidéo pour éviter toute fuite visuelle.
- **Sécurité de l'Environnement (RASP) :** Détection proactive des appareils rootés, du débogage USB (ADB) et des outils de piratage (Frida/Xposed).
- **Zéro Réseau (Confidentialité Totale) :** L'application ne possède aucune permission internet. Vos données ne quittent jamais votre téléphone.
- **Verrouillage Automatique :** L'application se verrouille instantanément et nettoie les données sensibles de la mémoire dès qu'elle passe en arrière-plan.
- **Vérification d'Intégrité :** Utilise l'API Google Play Integrity pour garantir que l'application n'a pas été modifiée ou compromise.
- **Interface Moderne :** Une expérience utilisateur fluide, rapide et sécurisée.
- **Zéro Log :** Aucune donnée n'est enregistrée dans les journaux système (logcat) pour une discrétion absolue.
- **Clavier Sécurisé :** Protection contre les enregistreurs de frappe (keyloggers).

## 🛠️ Spécifications Techniques

- **Langage :** 100% Kotlin
- **Interface :** Jetpack Compose avec Material Design 3.
- **Compatibilité :** Android 12 (API 31) et versions ultérieures.
- **Sécurité Matérielle :** 
    - **Master Key :** Stockée dans l'Android KeyStore, avec support StrongBox (puce de sécurité dédiée) si disponible.
    - **Chiffrement des Préférences :** AES-256 SIV pour les clés, AES-256 GCM pour les valeurs.
- **Gestion de la Mémoire :** Utilisation de structures de données sécurisées (`CharArray`) avec effacement manuel immédiat des mots de passe après usage.

## 📦 Installation & Utilisation

L'application est fournie sous forme de fichier APK signé pour une sécurité maximale.

1. Téléchargez le fichier `app-release.apk`.
2. Installez-le sur votre appareil Android.
3. Configurez votre accès biométrique lors du premier lancement.

---
*Note : Pour des raisons de sécurité, l'application refusera de s'exécuter sur un appareil dont la sécurité est compromise (Root activé ou options développeurs/ADB activées).*
