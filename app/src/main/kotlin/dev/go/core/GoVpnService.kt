package dev.go.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import hev.htproxy.TProxyService
import dev.go.core.mobile.Bridge
import dev.go.core.mobile.SocketProtector
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

class GoVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    private val bridge = Bridge()
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification())
        when (intent?.action) {
            ACTION_DISCONNECT -> worker.execute { stopTunnel() }
            ACTION_CONNECT -> {
                val raw = intent.getStringExtra(EXTRA_PROFILE)
                if (raw.isNullOrBlank()) {
                    stopTunnel()
                } else {
                    worker.execute { startTunnel(raw) }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(raw: String) {
        stopTunnel()
        try {
            bridge.setSocketProtector(object : SocketProtector {
                override fun protect(fd: Int): Boolean = this@GoVpnService.protect(fd)
            })
            bridge.connect(raw)
            val profile = JSONObject(raw)
            val socks = bridge.socksAddress()
            val parts = socks.substringAfterLast(':').toIntOrNull()
                ?: error("Invalid local SOCKS5 endpoint")
            val dns = profile.optString("dnsResolver", "1.1.1.1").ifBlank { "1.1.1.1" }

            val descriptor = Builder()
                .setSession("Go")
                .setMtu(1500)
                .addAddress("198.18.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(dns)
                .establish() ?: error("VPN interface creation was denied")
            tun = descriptor

            val config = File(cacheDir, "hev-socks5.yml")
            config.writeText(
                "tunnel:\n" +
                "  name: tun0\n" +
                "  mtu: 1500\n" +
                "  ipv4: 198.18.0.1\n" +
                "socks5:\n" +
                "  address: 127.0.0.1\n" +
                "  port: $parts\n" +
                "  udp: 'udp'\n" +
                "misc:\n" +
                "  log-level: warn\n"
            )
            check(TProxyService.TProxyStartService(config.absolutePath, descriptor.fd)) {
                "HEV tunnel failed to start"
            }
            running = true
            updateNotification("Go VPN connected")
            broadcastStatus("connected", "VPN connected")
        } catch (e: Exception) {
            stopTunnel()
            broadcastStatus("error", e.message ?: "Tunnel startup failed")
        }
    }

    private fun stopTunnel() {
        if (running || TProxyService.TProxyIsRunning()) {
            TProxyService.TProxyStopService()
        }
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        try { bridge.close() } catch (_: Exception) {}
        updateNotification("Go VPN disconnected")
        broadcastStatus("disconnected", "VPN disconnected")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(): Notification {
        val channelId = "go_vpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(channelId, "Go VPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("Go VPN")
            .setContentText("Starting tunnel")
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, notification().also {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                it.extras.putString(Notification.EXTRA_TEXT, text)
            }
        })
    }

    private fun broadcastStatus(state: String, message: String) {
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_MESSAGE, message)
        )
    }

    override fun onRevoke() {
        worker.execute { stopTunnel() }
        super.onRevoke()
    }

    override fun onDestroy() {
        worker.execute { stopTunnel() }
        worker.shutdown()
        super.onDestroy()
    }

    companion object {
        const val ACTION_CONNECT = "dev.go.core.action.CONNECT"
        const val ACTION_DISCONNECT = "dev.go.core.action.DISCONNECT"
        const val ACTION_STATUS = "dev.go.core.action.STATUS"
        const val EXTRA_PROFILE = "profile"
        const val EXTRA_STATE = "state"
        const val EXTRA_MESSAGE = "message"
        private const val NOTIFICATION_ID = 7001
    }
}
