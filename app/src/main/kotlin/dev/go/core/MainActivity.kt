package dev.go.core

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import org.json.JSONObject
import dev.go.core.mobile.Bridge

class MainActivity : Activity() {
    private lateinit var fields: LinearLayout
    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var username: EditText
    private lateinit var password: EditText
    private lateinit var privateKey: EditText
    private lateinit var passphrase: EditText
    private lateinit var proxyHost: EditText
    private lateinit var proxyPort: EditText
    private lateinit var sni: EditText
    private lateinit var payload: EditText
    private lateinit var tlsFingerprint: EditText
    private lateinit var hostKeyFingerprint: EditText
    private lateinit var keepAlive: EditText
    private lateinit var udpResolver: EditText
    private lateinit var dnsResolver: EditText
    private lateinit var mode: Spinner
    private lateinit var acceptAnyStatus: CheckBox
    private lateinit var verifyTLS: CheckBox
    private lateinit var udpForward: CheckBox
    private lateinit var dnsForward: CheckBox
    private lateinit var disableDelaySSH: CheckBox
    private lateinit var status: TextView
    private var pendingProfile: String? = null
    private var lockedProfileRaw: String? = null
    private var importedBlockRoot = false
    private val hiddenProfileViews = mutableListOf<android.view.View>()
    private val importBridge = Bridge()
    private var receiverRegistered = false
    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != GoVpnService.ACTION_STATUS) return
            status.text = intent.getStringExtra(GoVpnService.EXTRA_MESSAGE) ?: "VPN status changed"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }
        val scroll = ScrollView(this)
        fields = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(fields)
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        fields.addView(label("Go"))
        fields.addView(label("SSH tunnel profile"))

        mode = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_dropdown_item,
                listOf("Direct", "HTTP Proxy", "SSL", "Payload + SSL")
            )
        }
        val modeLabel = fieldLabel("Tunnel mode")
        fields.addView(modeLabel)
        fields.addView(mode)
        hiddenProfileViews.add(modeLabel)
        hiddenProfileViews.add(mode)

        fields.addView(Button(this).apply {
            text = "Import legacy .sks"
            setOnClickListener { chooseLegacyProfile() }
        })
        fields.addView(Button(this).apply {
            text = "Paste locked Go URI"
            setOnClickListener { pasteLockedURI() }
        })
        fields.addView(Button(this).apply {
            text = "Paste SSH URI"
            setOnClickListener { pasteSSHURI() }
        })
        fields.addView(Button(this).apply {
            text = "New profile"
            setOnClickListener { resetProfile() }
        })

        host = input("SSH host")
        port = input("SSH port", "22")
        username = input("SSH username")
        password = input("SSH password", password = true)
        privateKey = multiInput("SSH private key")
        passphrase = input("Private key passphrase", password = true)
        proxyHost = input("Proxy host")
        proxyPort = input("Proxy port")
        sni = input("SNI")
        payload = input("Custom payload")
        tlsFingerprint = input("TLS SHA-256 fingerprint (optional)")
        hostKeyFingerprint = input("SSH host-key SHA-256 (optional)")
        keepAlive = input("SSH keepalive seconds", "0")
        udpResolver = input("UDP gateway", "127.0.0.1:7300")
        dnsResolver = input("DNS resolver", "1.1.1.1")
        acceptAnyStatus = toggle("Accept any proxy status", true)
        verifyTLS = toggle("Verify TLS certificate", false)
        udpForward = toggle("UDP forwarding", true)
        dnsForward = toggle("DNS forwarding", true)
        disableDelaySSH = toggle("TCP_NODELAY", true)
        status = label("Disconnected")
        fields.addView(status)

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
        }
        actions.addView(Button(this).apply {
            text = "Connect"
            setOnClickListener { connect() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        actions.addView(Button(this).apply {
            text = "Disconnect"
            setOnClickListener { disconnect() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        actions.addView(Button(this).apply {
            text = "Export locked"
            setOnClickListener { exportLockedURI() }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(actions)
        setContentView(root)
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(GoVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(statusReceiver, filter)
        }
        receiverRegistered = true
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(statusReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    private fun input(hint: String, value: String = "", password: Boolean = false): EditText {
        val edit = EditText(this).apply {
            this.hint = hint
            setSingleLine(true)
            setText(value)
            if (password) inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        fields.addView(edit)
        hiddenProfileViews.add(edit)
        return edit
    }

    private fun multiInput(hint: String): EditText {
        val edit = EditText(this).apply {
            this.hint = hint
            setSingleLine(false)
            minLines = 4
            maxLines = 8
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        fields.addView(edit)
        hiddenProfileViews.add(edit)
        return edit
    }

    private fun toggle(text: String, checked: Boolean): CheckBox {
        val view = CheckBox(this).apply {
            this.text = text
            isChecked = checked
        }
        fields.addView(view)
        hiddenProfileViews.add(view)
        return view
    }

    private fun label(value: String) = TextView(this).apply {
        text = value
        textSize = 18f
        setPadding(0, 16, 0, 8)
    }

    private fun fieldLabel(value: String) = TextView(this).apply {
        text = value
        textSize = 14f
        setPadding(0, 12, 0, 0)
    }

    private fun buildProfileJson(): String {
        val selectedMode = when (mode.selectedItemPosition) {
            1 -> "proxy"
            2 -> "ssl"
            3 -> "payload+ssl"
            else -> "direct"
        }
        return JSONObject()
            .put("mode", selectedMode)
            .put("host", host.text.toString().trim())
            .put("port", port.text.toString().toIntOrNull() ?: 22)
            .put("username", username.text.toString())
            .put("password", password.text.toString())
            .put("privateKey", privateKey.text.toString())
            .put("passphrase", passphrase.text.toString())
            .put("proxyHost", proxyHost.text.toString().trim())
            .put("proxyPort", proxyPort.text.toString().toIntOrNull() ?: 0)
            .put("sni", sni.text.toString().trim())
            .put("payload", payload.text.toString())
            .put("tlsFingerprint", tlsFingerprint.text.toString().trim())
            .put("hostKeySha256", hostKeyFingerprint.text.toString().trim())
            .put("keepAliveSeconds", keepAlive.text.toString().toIntOrNull() ?: 0)
            .put("acceptAnyStatus", acceptAnyStatus.isChecked)
            .put("verifyTls", verifyTLS.isChecked)
            .put("disableDelaySSH", disableDelaySSH.isChecked)
            .put("udpForward", udpForward.isChecked)
            .put("udpResolver", udpResolver.text.toString().trim())
            .put("dnsForward", dnsForward.isChecked)
            .put("dnsResolver", dnsResolver.text.toString().trim())
            .put("blockRoot", importedBlockRoot)
            .toString()
    }

    private fun connect() {
        val profileJson = lockedProfileRaw ?: buildProfileJson()
        pendingProfile = profileJson
        val permission = VpnService.prepare(this)
        if (permission != null) {
            startActivityForResult(permission, VPN_PERMISSION_REQUEST)
        } else {
            startVpnService(profileJson)
        }
    }

    private fun chooseLegacyProfile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
            .setType("*/*")
            .addCategory(Intent.CATEGORY_OPENABLE)
        startActivityForResult(intent, LEGACY_PROFILE_REQUEST)
    }

    private fun applyImportedConfig(result: JSONObject) {
        val imported = result.getJSONObject("profile")
        lockedProfileRaw = null
        importedBlockRoot = result.optBoolean("blockRoot")
        imported.put("blockRoot", importedBlockRoot)
        imported.put("expiryUnixMilli", result.optLong("expiryUnixMilli", 0L))
        imported.put("message", result.optString("message"))
        mode.setSelection(
            when (imported.optString("mode")) {
                "proxy" -> 1
                "ssl" -> 2
                "payload+ssl" -> 3
                else -> 0
            }
        )
        host.setText(imported.optString("host"))
        port.setText(imported.optString("port", "22"))
        username.setText(imported.optString("username"))
        password.setText(imported.optString("password"))
        privateKey.setText(imported.optString("privateKey"))
        passphrase.setText(imported.optString("passphrase"))
        proxyHost.setText(imported.optString("proxyHost"))
        proxyPort.setText(imported.optString("proxyPort"))
        sni.setText(imported.optString("sni"))
        payload.setText(imported.optString("payload"))
        tlsFingerprint.setText(imported.optString("tlsFingerprint"))
        hostKeyFingerprint.setText(imported.optString("hostKeySha256"))
        keepAlive.setText(imported.optString("keepAliveSeconds", "0"))
        udpResolver.setText(imported.optString("udpResolver", "127.0.0.1:7300"))
        dnsResolver.setText(imported.optString("dnsResolver", "1.1.1.1"))
        acceptAnyStatus.isChecked = imported.optBoolean("acceptAnyStatus", true)
        verifyTLS.isChecked = imported.optBoolean("verifyTls", false)
        udpForward.isChecked = imported.optBoolean("udpForward", true)
        dnsForward.isChecked = imported.optBoolean("dnsForward", true)
        disableDelaySSH.isChecked = imported.optBoolean("disableDelaySSH", true)

        if (result.optBoolean("locked")) {
            lockedProfileRaw = imported.toString()
            hiddenProfileViews.forEach { it.visibility = android.view.View.GONE }
            status.text = result.optString("message").ifBlank { "Locked profile imported" }
        } else {
            hiddenProfileViews.forEach { it.visibility = android.view.View.VISIBLE }
            status.text = "Profile imported"
        }
    }

    private fun importLegacyProfile(uri: android.net.Uri) {
        try {
            val raw = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("Unable to read selected profile")
            applyImportedConfig(JSONObject(importBridge.importSKS(raw, 644L, System.currentTimeMillis())))
        } catch (e: Exception) {
            status.text = "Import failed: ${e.message ?: "invalid .sks profile"}"
        }
    }

    private fun resetProfile() {
        lockedProfileRaw = null
        importedBlockRoot = false
        hiddenProfileViews.forEach { it.visibility = android.view.View.VISIBLE }
        mode.setSelection(0)
        host.setText("")
        port.setText("22")
        username.setText("")
        password.setText("")
        privateKey.setText("")
        passphrase.setText("")
        proxyHost.setText("")
        proxyPort.setText("")
        sni.setText("")
        payload.setText("")
        tlsFingerprint.setText("")
        hostKeyFingerprint.setText("")
        keepAlive.setText("0")
        udpResolver.setText("127.0.0.1:7300")
        dnsResolver.setText("1.1.1.1")
        acceptAnyStatus.isChecked = true
        verifyTLS.isChecked = false
        udpForward.isChecked = true
        dnsForward.isChecked = true
        disableDelaySSH.isChecked = true
        status.text = "New profile"
    }

    private fun pasteSSHURI() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val uri = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim()
        if (uri.isNullOrBlank() || !uri.startsWith("ssh://")) {
            status.text = "Clipboard does not contain an SSH URI"
            return
        }
        try {
            val parsed = JSONObject(importBridge.parseSSHURI(uri))
            applyImportedConfig(
                JSONObject().put("profile", parsed).put("locked", false).put("blockRoot", false)
            )
        } catch (e: Exception) {
            status.text = "Import failed: ${e.message ?: "invalid SSH URI"}"
        }
    }

    private fun pasteLockedURI() {
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val uri = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim()
        if (uri.isNullOrBlank() || !uri.startsWith("go-ssh://locked/")) {
            status.text = "Clipboard does not contain a locked Go URI"
            return
        }
        val passcode = EditText(this).apply {
            hint = "Passcode (leave blank if none)"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        AlertDialog.Builder(this)
            .setTitle("Import locked profile")
            .setView(passcode)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Import") { _, _ ->
                try {
                    val result = JSONObject(
                        importBridge.importLockedURI(uri, passcode.text.toString(), System.currentTimeMillis())
                    )
                    applyImportedConfig(result)
                } catch (e: Exception) {
                    status.text = "Import failed: ${e.message ?: "invalid locked URI"}"
                }
            }
            .show()
    }

    private fun exportLockedURI() {
        val passcode = EditText(this).apply {
            hint = "Optional passcode"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val message = EditText(this).apply { hint = "Config message (optional)" }
        val expiry = EditText(this).apply {
            hint = "Expiry Unix milliseconds (0 = no expiry)"
            setText("0")
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
        }
        val dialogFields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(message)
            addView(expiry)
            addView(passcode)
        }
        AlertDialog.Builder(this)
            .setTitle("Export locked Go profile")
            .setView(dialogFields)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Export") { _, _ ->
                try {
                    val expiryValue = expiry.text.toString().toLongOrNull() ?: 0L
                    val uri = importBridge.exportLockedURI(
                        lockedProfileRaw ?: buildProfileJson(),
                        expiryValue,
                        message.text.toString(),
                        importedBlockRoot,
                        passcode.text.toString()
                    )
                    val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("Go locked profile", uri))
                    status.text = if (passcode.text.isNullOrEmpty()) {
                        "Locked URI copied; fields are hidden in the app but data is not encrypted"
                    } else {
                        "Encrypted locked URI copied"
                    }
                } catch (e: Exception) {
                    status.text = "Export failed: ${e.message ?: "invalid profile"}"
                }
            }
            .show()
    }

    private fun startVpnService(profile: String) {
        val intent = Intent(this, GoVpnService::class.java)
            .setAction(GoVpnService.ACTION_CONNECT)
            .putExtra(GoVpnService.EXTRA_PROFILE, profile)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        status.text = "Starting VPN..."
    }

    private fun disconnect() {
        startService(
            Intent(this, GoVpnService::class.java)
                .setAction(GoVpnService.ACTION_DISCONNECT)
        )
        status.text = "Disconnecting..."
    }

    @Deprecated("Deprecated in Android")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == LEGACY_PROFILE_REQUEST && resultCode == RESULT_OK) {
            data?.data?.let { importLegacyProfile(it) }
            return
        }
        if (requestCode == VPN_PERMISSION_REQUEST) {
            val profile = pendingProfile
            pendingProfile = null
            if (resultCode == RESULT_OK && profile != null) {
                startVpnService(profile)
            } else {
                status.text = "VPN permission denied"
            }
        }
    }

    companion object {
        private const val VPN_PERMISSION_REQUEST = 4101
        private const val LEGACY_PROFILE_REQUEST = 4102
    }
}
