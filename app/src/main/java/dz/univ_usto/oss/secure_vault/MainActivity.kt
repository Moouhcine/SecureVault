package dz.univ_usto.oss.secure_vault

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import dz.univ_usto.oss.secure_vault.security.BiometricCryptoManager
import dz.univ_usto.oss.secure_vault.security.CrashReporter
import dz.univ_usto.oss.secure_vault.security.IntegrityChecker
import dz.univ_usto.oss.secure_vault.security.PasswordGenerator
import dz.univ_usto.oss.secure_vault.security.SecurityEnvironmentChecker
import dz.univ_usto.oss.secure_vault.security.VaultManager
import dz.univ_usto.oss.secure_vault.ui.theme.SecureVaultTheme
import javax.crypto.Cipher

class MainActivity : AppCompatActivity() {

    private var vaultManager: VaultManager? = null
    private var isUnlocked by mutableStateOf(false)
    private var isEnvironmentCompromised by mutableStateOf(false)
    private var isBiometricAvailable by mutableStateOf(true)
    private var isIntegrityChecked by mutableStateOf(false)
    private var integrityCheckFailed by mutableStateOf(false)
    private var crashReport by mutableStateOf<String?>(null)
    private var isClearingClipboard = false

    private val allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        // Protection against Tapjacking (Overlays)
        findViewById<View>(android.R.id.content).filterTouchesWhenObscured = true
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        CrashReporter.init(this)
        crashReport = CrashReporter.loadReport(this)

        vaultManager = try {
            VaultManager(this)
        } catch (_: Exception) {
            null
        }

        checkSecurity()

        enableEdgeToEdge()
        setContent {
            SecureVaultTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    when {
                        crashReport != null -> CrashReportScreen(report = crashReport!!, onDismiss = { CrashReporter.clearReport(this); crashReport = null })
                        isEnvironmentCompromised || integrityCheckFailed -> CompromisedScreen()
                        !isIntegrityChecked -> IntegrityCheckScreen()
                        !isBiometricAvailable -> BiometricUnavailableScreen()
                        !isUnlocked -> LockedScreen(onAuthenticate = { authenticateMain() })
                        else -> VaultHome(vaultManager!!)
                    }
                }
            }
        }
    }

    private fun checkSecurity() {
        isEnvironmentCompromised = !SecurityEnvironmentChecker.isEnvironmentSafe(this)
        isBiometricAvailable = BiometricManager.from(this).canAuthenticate(allowedAuthenticators) == BiometricManager.BIOMETRIC_SUCCESS
        
        if (IntegrityChecker.isIntegrityEnforced(this)) {
            IntegrityChecker.requestIntegrityToken(this, { isIntegrityChecked = true; integrityCheckFailed = false }, { isIntegrityChecked = true; integrityCheckFailed = true })
        } else {
            isIntegrityChecked = true
        }
    }

    private fun authenticateMain() {
        showBiometricPrompt("Unlock Vault", "Authenticate to access your secrets", BiometricCryptoManager.getEncryptCipher()) { result ->
            if (result.cryptoObject?.cipher != null) {
                isUnlocked = true
            }
        }
    }

    // Public method to be called from Composable
    fun performBiometricAction(title: String, subtitle: String, cipher: Cipher?, onSucceeded: (BiometricPrompt.AuthenticationResult) -> Unit) {
        showBiometricPrompt(title, subtitle, cipher, onSucceeded)
    }

    private fun showBiometricPrompt(title: String, subtitle: String, cipher: Cipher?, onSucceeded: (BiometricPrompt.AuthenticationResult) -> Unit) {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSucceeded(result)
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(allowedAuthenticators)
            .apply { if ((allowedAuthenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0) setNegativeButtonText("Cancel") }
            .build()

        if (cipher != null) {
            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } else {
            biometricPrompt.authenticate(promptInfo)
        }
    }

    private fun clearClipboard() {
        val clipboard = getSystemService<ClipboardManager>() ?: return
        if (isClearingClipboard) return
        try {
            isClearingClipboard = true
            clipboard.clearPrimaryClip()
        } catch (_: Exception) {
        } finally {
            isClearingClipboard = false
        }
    }

    override fun onResume() { super.onResume(); checkSecurity(); clearClipboard() }
    override fun onPause() { super.onPause(); isUnlocked = false; clearClipboard() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultHome(vaultManager: VaultManager) {
    val context = LocalActivity.current as MainActivity
    var credentials by remember { mutableStateOf(vaultManager.getAllCredentialTitles()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var revealedCredential by remember { mutableStateOf<VaultManager.Credential?>(null) }

    Scaffold(
        topBar = { CenterAlignedTopAppBar(title = { Text("SecureVault") }) },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) { Icon(Icons.Default.Add, "Add") }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
                items(credentials) { title ->
                    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(title, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                            IconButton(onClick = {
                                val iv = vaultManager.getIvForCredential(title)
                                if (iv != null) {
                                    val cipher = BiometricCryptoManager.getDecryptCipher(iv)
                                    context.performBiometricAction("View Credential", "Authenticate to reveal password", cipher) { result ->
                                        revealedCredential = vaultManager.getCredential(title, result.cryptoObject!!.cipher!!)
                                    }
                                }
                            }) { Icon(Icons.Default.Visibility, "View") }
                            IconButton(onClick = {
                                context.performBiometricAction("Delete Credential", "Confirm deletion of $title", null) {
                                    vaultManager.deleteCredential(title)
                                    credentials = vaultManager.getAllCredentialTitles()
                                }
                            }) { Icon(Icons.Default.Delete, "Delete", tint = MaterialTheme.colorScheme.error) }
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        AddCredentialDialog(
            onDismiss = { showAddDialog = false },
            onSave = { title, user, email, pass ->
                val cipher = BiometricCryptoManager.getEncryptCipher()
                context.performBiometricAction("Save Credential", "Authorize encryption with biometrics", cipher) { result ->
                    vaultManager.saveCredential(title, user, email, pass, result.cryptoObject!!.cipher!!)
                    credentials = vaultManager.getAllCredentialTitles()
                    showAddDialog = false
                }
            }
        )
    }

    if (revealedCredential != null) {
        var passwordVisible by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { revealedCredential = null },
            title = { Text(revealedCredential!!.title) },
            text = {
                Column {
                    if (revealedCredential!!.username.isNotEmpty()) {
                        Text("User: ${revealedCredential!!.username}")
                    }
                    if (revealedCredential!!.email.isNotEmpty()) {
                        Text("Email: ${revealedCredential!!.email}")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Pass: ")
                        Text(
                            text = if (passwordVisible) revealedCredential!!.password else "••••••••",
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = "Toggle Visibility"
                            )
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { revealedCredential = null }) { Text("Close") } }
        )
    }
}

@Composable
fun AddCredentialDialog(onDismiss: () -> Unit, onSave: (String, CharArray, CharArray, CharArray) -> Unit) {
    var title by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    
    val isFormValid = title.isNotBlank() && pass.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New Account") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SecureOutlinedTextField(
                    value = title, 
                    onValueChange = { title = it }, 
                    label = { Text("Title *") },
                    isError = title.isBlank()
                )
                SecureOutlinedTextField(value = user, onValueChange = { user = it }, label = { Text("Username") })
                SecureOutlinedTextField(value = email, onValueChange = { email = it }, label = { Text("Email") }, keyboardType = KeyboardType.Email)
                SecureOutlinedTextField(
                    value = pass, 
                    onValueChange = { pass = it }, 
                    label = { Text("Password *") }, 
                    isSecret = true, 
                    keyboardType = KeyboardType.Password,
                    isError = pass.isBlank()
                )
                Button(
                    onClick = { pass = PasswordGenerator.generate() }, 
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.medium
                ) { 
                    Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Generate Secure Password") 
                }
            }
        },
        confirmButton = { 
            Button(
                onClick = { onSave(title, user.toCharArray(), email.toCharArray(), pass.toCharArray()) },
                enabled = isFormValid
            ) { 
                Text("Save") 
            } 
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
fun SecureOutlinedTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    isSecret: Boolean = false,
    isError: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text
) {
    val context = LocalContext.current
    val clipboard = context.getSystemService<ClipboardManager>()
    var passwordVisible by remember { mutableStateOf(false) }

    // Context menu disabled (copy/paste/cut)
    CompositionLocalProvider(
        androidx.compose.ui.platform.LocalTextToolbar provides object : androidx.compose.ui.platform.TextToolbar {
            override fun hide() {}
            override fun showMenu(rect: androidx.compose.ui.geometry.Rect, onCopyRequested: (() -> Unit)?, onPasteRequested: (() -> Unit)?, onCutRequested: (() -> Unit)?, onSelectAllRequested: (() -> Unit)?) {}
            override val status: androidx.compose.ui.platform.TextToolbarStatus = androidx.compose.ui.platform.TextToolbarStatus.Hidden
        }
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {
                // Blocks massive text pasting
                if (it.length - value.length > 1) return@OutlinedTextField
                onValueChange(it)
            },
            label = label,
            isError = isError,
            modifier = modifier
                .fillMaxWidth()
                .onFocusChanged {
                    if (it.isFocused) {
                        try { clipboard?.setPrimaryClip(ClipData.newPlainText("", "")) } catch (_: Exception) {}
                    }
                },
            singleLine = true,
            trailingIcon = if (isSecret) {
                {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = "Toggle Visibility"
                        )
                    }
                }
            } else null,
            keyboardOptions = KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = keyboardType,
                imeAction = androidx.compose.ui.text.input.ImeAction.Default
            ),
            visualTransformation = if (isSecret && !passwordVisible) PasswordVisualTransformation() else VisualTransformation.None,
            shape = MaterialTheme.shapes.medium
        )
    }
}

@Composable fun LockedScreen(onAuthenticate: () -> Unit) { Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) { Icon(Icons.Default.Lock, null, modifier = Modifier.size(100.dp), tint = MaterialTheme.colorScheme.primary); Spacer(Modifier.height(24.dp)); Text("Vault Locked", fontSize = 24.sp, fontWeight = FontWeight.Bold); Spacer(Modifier.height(32.dp)); Button(onClick = onAuthenticate) { Text("Unlock") } } }
@Composable fun CompromisedScreen() { Column(modifier = Modifier.fillMaxSize().background(Color(0xFFB00020)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) { Text("SECURITY ALERT", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold); Text("Device Compromised.", color = Color.White) } }
@Composable fun IntegrityCheckScreen() { Column(modifier = Modifier.fillMaxSize().background(Color(0xFF1A237E)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) { Text("Checking Integrity...", color = Color.White); CircularProgressIndicator(color = Color.White) } }
@Composable fun BiometricUnavailableScreen() { Column(modifier = Modifier.fillMaxSize().background(Color(0xFF4E342E)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) { Text("Biometrics Required.", color = Color.White) } }
@Composable fun CrashReportScreen(report: String, onDismiss: () -> Unit) { Column(modifier = Modifier.fillMaxSize().background(Color(0xFF263238)).padding(16.dp)) { Text("Diagnostic", color = Color.White, fontSize = 24.sp); Text(report.take(1000), color = Color.White); Button(onClick = onDismiss) { Text("Close") } } }
