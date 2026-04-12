package dz.univ_usto.oss.secure_vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalTextToolbar
import androidx.compose.ui.platform.TextToolbar
import androidx.compose.ui.platform.TextToolbarStatus
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import androidx.documentfile.provider.DocumentFile
import dz.univ_usto.oss.secure_vault.security.BiometricCryptoManager
import dz.univ_usto.oss.secure_vault.security.CrashReporter
import dz.univ_usto.oss.secure_vault.security.DocumentManager
import dz.univ_usto.oss.secure_vault.security.IntegrityChecker
import dz.univ_usto.oss.secure_vault.security.PasswordGenerator
import dz.univ_usto.oss.secure_vault.security.SecurityEnvironmentChecker
import dz.univ_usto.oss.secure_vault.security.VaultManager
import dz.univ_usto.oss.secure_vault.ui.theme.SecureVaultTheme

class MainActivity : AppCompatActivity() {

    private var vaultManager: VaultManager? = null
    private var isUnlocked by mutableStateOf(false)
    private var isEnvironmentCompromised by mutableStateOf(false)
    private var isBiometricAvailable by mutableStateOf(true)
    private var isIntegrityChecked by mutableStateOf(false)
    private var integrityCheckFailed by mutableStateOf(false)
    private var crashReport by mutableStateOf<String?>(null)
    private var isClearingClipboard = false

    private val clipboardListener = ClipboardManager.OnPrimaryClipChangedListener {
        clearClipboard()
    }

    private val allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS

        CrashReporter.init(this)
        crashReport = CrashReporter.loadReport(this)

        vaultManager = try {
            VaultManager(this)
        } catch (e: Exception) {
            crashReport = "Vault init failed:\n${e.stackTraceToString()}"
            null
        }

        try {
            if (!SecurityEnvironmentChecker.isEnvironmentSafe(this)) {
                isEnvironmentCompromised = true
                isUnlocked = false
            }
        } catch (_: Exception) {
            isEnvironmentCompromised = true
            isUnlocked = false
        }

        isBiometricAvailable = try {
            val biometricStatus = BiometricManager.from(this).canAuthenticate(allowedAuthenticators)
            biometricStatus == BiometricManager.BIOMETRIC_SUCCESS
        } catch (_: Exception) {
            false
        }

        if (IntegrityChecker.isIntegrityEnforced(this)) {
            IntegrityChecker.requestIntegrityToken(
                context = this,
                onSuccess = {
                    isIntegrityChecked = true
                    integrityCheckFailed = false
                },
                onFailure = {
                    isIntegrityChecked = true
                    integrityCheckFailed = true
                    isUnlocked = false
                }
            )
        } else {
            isIntegrityChecked = true
            integrityCheckFailed = false
        }

        enableEdgeToEdge()
        setContent {
            CompositionLocalProvider(LocalTextToolbar provides NoTextToolbar) {
                SecureVaultTheme {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        when {
                            crashReport != null -> CrashReportScreen(
                                report = crashReport.orEmpty(),
                                onDismiss = {
                                    CrashReporter.clearReport(this@MainActivity)
                                    crashReport = null
                                }
                            )
                            isEnvironmentCompromised || integrityCheckFailed -> CompromisedScreen()
                            !isIntegrityChecked -> IntegrityCheckScreen()
                            !isBiometricAvailable -> BiometricUnavailableScreen()
                            !isUnlocked -> LockedScreen(onAuthenticate = { showBiometricPrompt() })
                            else -> {
                                val manager = vaultManager
                                if (manager != null) {
                                    VaultHome(manager)
                                } else {
                                    CrashReportScreen(
                                        report = crashReport.orEmpty(),
                                        onDismiss = {
                                            CrashReporter.clearReport(this@MainActivity)
                                            crashReport = null
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        getSystemService<ClipboardManager>()?.addPrimaryClipChangedListener(clipboardListener)
        clearClipboard()
    }

    override fun onStop() {
        getSystemService<ClipboardManager>()?.removePrimaryClipChangedListener(clipboardListener)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        try {
            if (!SecurityEnvironmentChecker.isEnvironmentSafe(this)) {
                isEnvironmentCompromised = true
                isUnlocked = false
            }
        } catch (_: Exception) {
            isEnvironmentCompromised = true
            isUnlocked = false
        }

        isBiometricAvailable = try {
            val biometricStatus = BiometricManager.from(this).canAuthenticate(allowedAuthenticators)
            biometricStatus == BiometricManager.BIOMETRIC_SUCCESS
        } catch (_: Exception) {
            false
        }

        if (!isUnlocked && !isEnvironmentCompromised && isBiometricAvailable) {
            showBiometricPrompt()
        }

        clearClipboard()
    }

    override fun onPause() {
        super.onPause()
        isUnlocked = false
        clearClipboard()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            clearClipboard()
        }
    }

    private fun showBiometricPrompt() {
        if (isEnvironmentCompromised || !isBiometricAvailable || !isIntegrityChecked) return

        val cipher = try {
            BiometricCryptoManager.createCipher()
        } catch (_: Exception) {
            isEnvironmentCompromised = true
            isUnlocked = false
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    if (result.cryptoObject?.cipher != null) {
                        isUnlocked = true
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    isUnlocked = false
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("SecureVault Access")
            .setSubtitle("Authenticate to access your secrets")
            .setAllowedAuthenticators(allowedAuthenticators)
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun clearClipboard() {
        val clipboard = getSystemService<ClipboardManager>() ?: return
        if (isClearingClipboard) return
        try {
            isClearingClipboard = true
            clipboard.clearPrimaryClip()
        } catch (_: Exception) {
            try {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            } catch (_: Exception) {
            }
        } finally {
            isClearingClipboard = false
        }
    }
}

private object NoTextToolbar : TextToolbar {
    override val status: TextToolbarStatus = TextToolbarStatus.Hidden
    override fun showMenu(rect: androidx.compose.ui.geometry.Rect, onCopyRequested: (() -> Unit)?, onPasteRequested: (() -> Unit)?, onCutRequested: (() -> Unit)?, onSelectAllRequested: (() -> Unit)?) {}
    override fun hide() {}
}

@Composable
fun LockedScreen(onAuthenticate: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(Icons.Default.Lock, contentDescription = "Locked", modifier = Modifier.size(100.dp), tint = MaterialTheme.colorScheme.primary)
        Spacer(modifier = Modifier.height(24.dp))
        Text("Vault is Locked", fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(32.dp))
        Button(onClick = onAuthenticate) { Text("Unlock with Biometrics") }
    }
}

@Composable
fun CompromisedScreen() {
    Column(modifier = Modifier.fillMaxSize().background(Color(0xFFB00020)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Text("SECURITY ALERT", color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.ExtraBold)
        Spacer(modifier = Modifier.height(16.dp))
        Text("Device Environment Compromised (Root/Debugger/ADB detected).\nAccess Blocked for safety.", color = Color.White, modifier = Modifier.padding(16.dp), textAlign = TextAlign.Center)
    }
}

@Composable
fun IntegrityCheckScreen() {
    Column(modifier = Modifier.fillMaxSize().background(Color(0xFF1A237E)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Text("INTEGRITY CHECK", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        Spacer(modifier = Modifier.height(16.dp))
        Text("Verifying device integrity...", color = Color.White, modifier = Modifier.padding(16.dp), textAlign = TextAlign.Center)
        Spacer(modifier = Modifier.height(12.dp))
        CircularProgressIndicator(color = Color.White)
    }
}

@Composable
fun BiometricUnavailableScreen() {
    Column(modifier = Modifier.fillMaxSize().background(Color(0xFF4E342E)), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Text("BIOMETRIC REQUIRED", color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.ExtraBold)
        Spacer(modifier = Modifier.height(16.dp))
        Text("No strong biometric is available on this device.\nAccess is blocked in strict mode.", color = Color.White, modifier = Modifier.padding(16.dp), textAlign = TextAlign.Center)
    }
}

@Composable
fun CrashReportScreen(report: String, onDismiss: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().background(Color(0xFF263238)).padding(16.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Text("DIAGNOSTIC", color = Color.White, fontSize = 26.sp, fontWeight = FontWeight.ExtraBold)
        Spacer(modifier = Modifier.height(12.dp))
        Text(report.take(2000), color = Color.White, textAlign = TextAlign.Start)
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onDismiss) { Text("Close") }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultHome(vaultManager: VaultManager) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("Accounts", "Documents")

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(title = { Text("SecureVault") })
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            PrimaryTabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(selected = selectedTab == index, onClick = { selectedTab = index }, text = { Text(title) })
                }
            }
            when (selectedTab) {
                0 -> AccountsScreen(vaultManager)
                1 -> DocumentsScreen()
            }
        }
    }
}

@Composable
fun AccountsScreen(vaultManager: VaultManager) {
    var credentials by remember { mutableStateOf(vaultManager.getAllCredentialTitles()) }
    var showAddDialog by remember { mutableStateOf(false) }
    var revealedValue by remember { mutableStateOf<String?>(null) }
    var revealedTitle by remember { mutableStateOf("") }
    var revealedUsername by remember { mutableStateOf<String?>(null) }
    var revealedEmail by remember { mutableStateOf<String?>(null) }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            items(credentials) { secretTitle ->
                Card(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Row(modifier = Modifier.padding(16.dp).fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(secretTitle, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        IconButton(onClick = { 
                            revealedTitle = secretTitle
                            val credential = vaultManager.getCredential(secretTitle)
                            revealedUsername = credential?.username
                            revealedEmail = credential?.email
                            revealedValue = credential?.password
                        }) { Icon(Icons.Default.Visibility, contentDescription = "View") }
                        IconButton(onClick = {
                            vaultManager.deleteCredential(secretTitle)
                            credentials = vaultManager.getAllCredentialTitles()
                        }) { Icon(Icons.Default.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
        FloatingActionButton(onClick = { showAddDialog = true }, modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)) {
            Icon(Icons.Default.Add, contentDescription = "Add Account")
        }
    }

    if (showAddDialog) {
        AddCredentialDialog(
            onDismiss = { showAddDialog = false },
            onSave = { title, usernameChars, emailChars, passwordChars ->
                vaultManager.saveCredential(title, usernameChars, emailChars, passwordChars)
                credentials = vaultManager.getAllCredentialTitles()
                showAddDialog = false
            }
        )
    }

    if (revealedValue != null) {
        AlertDialog(
            onDismissRequest = { revealedValue = null },
            title = { Text(revealedTitle) },
            text = { Text("Username: $revealedUsername\nEmail: $revealedEmail\nPassword: $revealedValue\n\n(Note: Copy/Paste disabled for security)") },
            confirmButton = { TextButton(onClick = { revealedValue = null }) { Text("Close") } }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DocumentsScreen() {
    val context = LocalContext.current
    val manager = remember { DocumentManager(context) }
    var documents by remember { mutableStateOf(manager.listDocuments()) }
    var pendingExportId by remember { mutableStateOf<String?>(null) }
    var menuExpandedForId by remember { mutableStateOf<String?>(null) }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val data = result.data
        val uri = data?.data
        if (uri != null) {
            val persistedFlags = buildList {
                if ((data.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0) {
                    add(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                if ((data.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0) {
                    add(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                }
            }.fold(0) { acc, flag -> acc or flag }

            try {
                if (persistedFlags != 0) {
                    context.contentResolver.takePersistableUriPermission(uri, persistedFlags)
                }
            } catch (_: Exception) {
            }
            val doc = DocumentFile.fromSingleUri(context, uri)
            val name = doc?.name ?: "document"
            val mime = doc?.type ?: "application/octet-stream"
            val importResult = manager.importDocument(uri, name, mime)
            if (importResult.success) {
                documents = manager.listDocuments()
                Toast.makeText(context, importResult.message, Toast.LENGTH_LONG).show()
            } else {
                val error = manager.getLastError() ?: "Import failed"
                Toast.makeText(context, error, Toast.LENGTH_SHORT).show()
            }
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri: Uri? ->
        val id = pendingExportId
        if (uri != null && id != null) {
            if (manager.exportDocument(id, uri)) {
                documents = manager.listDocuments()
                Toast.makeText(context, "Document moved out of the vault", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(context, "Export failed", Toast.LENGTH_SHORT).show()
            }
        }
        pendingExportId = null
    }

    Box(modifier = Modifier.fillMaxSize()) {
        LazyColumn(modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            items(documents) { doc ->
                Card(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
                ) {
                    Row(modifier = Modifier.padding(16.dp).fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Description, contentDescription = null)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(doc.displayName, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))

                        Box {
                            IconButton(onClick = { menuExpandedForId = doc.id }) {
                                Icon(Icons.Default.MoreVert, contentDescription = "Options")
                            }
                            DropdownMenu(
                                expanded = menuExpandedForId == doc.id,
                                onDismissRequest = { menuExpandedForId = null }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Restore outside vault") },
                                    leadingIcon = { Icon(Icons.Default.FileDownload, null) },
                                    onClick = {
                                        menuExpandedForId = null
                                        val exported = manager.exportDocumentToOriginal(doc.id)
                                        if (!exported) {
                                            pendingExportId = doc.id
                                            exportLauncher.launch(doc.displayName)
                                        } else {
                                            documents = manager.listDocuments()
                                            Toast.makeText(context, "Document restored to its original location", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Delete") },
                                    leadingIcon = { Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.error) },
                                    onClick = {
                                        menuExpandedForId = null
                                        manager.deleteDocument(doc.id)
                                        documents = manager.listDocuments()
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }
        FloatingActionButton(
            onClick = {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
                    addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
                }
                importLauncher.launch(intent)
            },
            modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
        ) {
            Icon(Icons.Default.Add, contentDescription = "Import Document")
        }
    }
}

@Composable
fun AddCredentialDialog(onDismiss: () -> Unit, onSave: (String, CharArray, CharArray, CharArray) -> Unit) {
    var title by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New Credential") },
        text = {
            Column {
                SecureOutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("* Title") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                SecureOutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username") },
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                SecureOutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Email") },
                    modifier = Modifier.fillMaxWidth(),
                    keyboardType = KeyboardType.Email
                )
                Spacer(modifier = Modifier.height(8.dp))
                SecureOutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("* Password") },
                    modifier = Modifier.fillMaxWidth(),
                    isSecret = true,
                    keyboardType = KeyboardType.Password
                )
                Spacer(modifier = Modifier.height(8.dp))
                Button(onClick = { password = PasswordGenerator.generate(16) }, modifier = Modifier.fillMaxWidth()) { Text("Generate Strong Password") }
            }
        },
        confirmButton = {
            Button(onClick = {
                if (title.isNotBlank() && password.isNotBlank()) {
                    onSave(title, username.toCharArray(), email.toCharArray(), password.toCharArray())
                    title = ""
                    username = ""
                    email = ""
                    password = ""
                }
            }) { Text("Save") }
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
    keyboardType: KeyboardType = KeyboardType.Text
) {
    val context = LocalContext.current
    val clipboard = context.getSystemService<ClipboardManager>()
    OutlinedTextField(
        value = value,
        onValueChange = {
            // Reject multi-character inserts to block paste events from keyboards and IMEs.
            if (it.length - value.length > 1) return@OutlinedTextField
            try {
                clipboard?.setPrimaryClip(ClipData.newPlainText("", ""))
            } catch (_: Exception) {
            }
            onValueChange(it)
        },
        label = label,
        modifier = modifier.onFocusChanged {
            if (it.isFocused) {
                try {
                    clipboard?.setPrimaryClip(ClipData.newPlainText("", ""))
                } catch (_: Exception) {
                }
            }
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            autoCorrectEnabled = false,
            keyboardType = keyboardType
        ),
        visualTransformation = if (isSecret) {
            PasswordVisualTransformation()
        } else {
            VisualTransformation.None
        }
    )
}
