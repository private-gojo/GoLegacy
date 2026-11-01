package dev.go.core

import android.app.Activity
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.Button
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
    private lateinit var proxyHost: EditText
    private lateinit var proxyPort: EditText
    private lateinit var sni: EditText
    private lateinit var payload: EditText
    private lateinit var udpResolver: EditText
    private lateinit var dnsResolver: EditText
    private lateinit var mode: Spinner
    private lateinit var status: TextView
    private var pendingProfile: String? = null
    private var lockedProfileRaw: String? = null
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

        host = input("SSH host")
        port = input("SSH port", "22")
        username = input("SSH username")
        password = input("SSH password", password = true)
        proxyHost = input("Proxy host")
        proxyPort = input("Proxy port")
        sni = input("SNI")
        payload = input("Custom payload")
        udpResolver = input("UDP gateway", "127.0.0.1:7300")
        dnsResolver = input("DNS resolver", "1.1.1.1")
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

    private fun connect() {
        val selectedMode = when (mode.selectedItemPosition) {
            1 -> "proxy"
            2 -> "ssl"
            3 -> "payload+ssl"
            else -> "direct"
        }
        val profile = JSONObject()
            .put("mode", selectedMode)
            .put("host", host.text.toString().trim())
            .put("port", port.text.toString().toIntOrNull() ?: 22)
            .put("username", username.text.toString())
            .put("password", password.text.toString())
            .put("proxyHost", proxyHost.text.toString().trim())
            .put("proxyPort", proxyPort.text.toString().toIntOrNull() ?: 0)
            .put("sni", sni.text.toString().trim())
            .put("payload", payload.text.toString())
            .put("acceptAnyStatus", true)
            .put("udpForward", true)
            .put("udpResolver", udpResolver.text.toString().trim())
            .put("dnsForward", true)
            .put("dnsResolver", dnsResolver.text.toString().trim())
            .toString()

        val profileJson = lockedProfileRaw ?: profile
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

    private fun importLegacyProfile(uri: android.net.Uri) {
        try {
            val raw = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: error("Unable to read selected profile")
            val result = JSONObject(importBridge.importSKS(raw, 644L, System.currentTimeMillis()))
            val imported = result.getJSONObject("profile")
            lockedProfileRaw = null
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
            proxyHost.setText(imported.optString("proxyHost"))
            proxyPort.setText(imported.optString("proxyPort"))
            sni.setText(imported.optString("sni"))
            payload.setText(imported.optString("payload"))
            udpResolver.setText(imported.optString("udpResolver", "127.0.0.1:7300"))
            dnsResolver.setText(imported.optString("dnsResolver", "1.1.1.1"))

            if (result.optBoolean("locked")) {
                imported.put("blockRoot", result.optBoolean("blockRoot"))
                lockedProfileRaw = imported.toString()
                hiddenProfileViews.forEach { it.visibility = android.view.View.GONE }
                status.text = result.optString("message").ifBlank { "Locked profile imported" }
            } else {
                hiddenProfileViews.forEach { it.visibility = android.view.View.VISIBLE }
                status.text = "Legacy profile imported"
            }
        } catch (e: Exception) {
            status.text = "Import failed: ${e.message ?: "invalid .sks profile"}"
        }
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
