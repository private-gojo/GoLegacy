package dev.go.core

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
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
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val bridge = Bridge()
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
        fields.addView(fieldLabel("Tunnel mode"))
        fields.addView(mode)

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

    private fun input(hint: String, value: String = "", password: Boolean = false): EditText {
        val edit = EditText(this).apply {
            this.hint = hint
            setSingleLine(true)
            setText(value)
            if (password) inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        fields.addView(edit)
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

        status.text = "Connecting..."
        worker.execute {
            try {
                bridge.connect(profile.toString())
                val address = bridge.socksAddress()
                main.post { status.text = "SSH connected · SOCKS5 $address" }
            } catch (e: Exception) {
                main.post { status.text = "Connection failed: ${e.message ?: "unknown error"}" }
            }
        }
    }

    private fun disconnect() {
        worker.execute {
            try {
                bridge.close()
                main.post { status.text = "Disconnected" }
            } catch (e: Exception) {
                main.post { status.text = "Disconnect error: ${e.message ?: "unknown error"}" }
            }
        }
    }

    override fun onDestroy() {
        worker.execute { bridge.close() }
        worker.shutdown()
        super.onDestroy()
    }
}
