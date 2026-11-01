package dev.go.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
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
    private val mainHandler = Handler(Looper.getMainLooper())
    private var expiryRunnable: Runnable? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    @Volatile private var stopRequested = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification("Starting tunnel"))
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopRequested = true
                worker.execute { stopTunnel() }
            }
            ACTION_CONNECT -> {
                val raw = intent.getStringExtra(EXTRA_PROFILE)
                stopRequested = true
                if (raw.isNullOrBlank()) {
                    worker.execute { stopTunnel() }
                } else {
                    worker.execute {
                        stopRequested = false
                        startTunnel(raw)
                    }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(raw: String) {
        val expiry = JSONObject(raw).optLong("expiryUnixMilli", 0L)
        if (expiry > 0L && System.currentTimeMillis() >= expiry) {
            broadcastStatus("error", "Profile expired")
            stopTunnel()
            return
        }
        var retryDelay = 1_000L
        while (!stopRequested) {
            try {
                startTunnelOnce(raw)
                return
            } catch (e: Exception) {
                cleanupTunnel()
                broadcastStatus("retrying", e.message ?: "Connection failed")
                updateNotification("Reconnecting in ${retryDelay / 1000}s")
                var elapsed = 0L
                while (elapsed < retryDelay && !stopRequested) {
                    Thread.sleep(250)
                    elapsed += 250
                }
                retryDelay = (retryDelay * 2).coerceAtMost(30_000L)
            }
        }
    }

    private fun startTunnelOnce(raw: String) {
        bridge.setSocketProtector(object : SocketProtector {
            override fun protect(fd: Long): Boolean = this@GoVpnService.protect(fd.toInt())
        })
        bridge.connect(raw)
        val profile = JSONObject(raw)
        val socks = bridge.socksAddress()
        val port = socks.substringAfterLast(':').toIntOrNull()
            ?: error("Invalid local SOCKS5 endpoint")
        val dns = profile.optString("dnsResolver", "1.1.1.1").ifBlank { "1.1.1.1" }

        val builder = Builder()
            .setSession("Go")
            .setMtu(1500)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
        if (profile.optBoolean("dnsForward", true)) builder.addDnsServer(dns)
        val descriptor = builder.establish() ?: error("VPN interface creation was denied")
        tun = descriptor

        val config = File(cacheDir, "hev-socks5.yml")
        config.writeText(
            "tunnel:\n" +
            "  name: tun0\n" +
            "  mtu: 1500\n" +
            "  ipv4: 198.18.0.1\n" +
            "socks5:\n" +
            "  address: 127.0.0.1\n" +
            "  port: $port\n" +
            "  udp: 'udp'\n" +
            "misc:\n" +
            "  log-level: warn\n"
        )
        check(TProxyService.TProxyStartService(config.absolutePath, descriptor.fd)) {
            "HEV tunnel failed to start"
        }
        running = true
        if (profile.optLong("expiryUnixMilli", 0L) > 0L) {
            val delay = (profile.optLong("expiryUnixMilli") - System.currentTimeMillis()).coerceAtLeast(0L)
            expiryRunnable = Runnable {
                stopRequested = true
                worker.execute { stopTunnel() }
            }
            mainHandler.postDelayed(expiryRunnable!!, delay)
        }
        updateNotification("Go VPN connected")
        broadcastStatus("connected", "VPN connected")
    }

    private fun cleanupTunnel() {
        if (running || TProxyService.TProxyIsRunning()) {
            TProxyService.TProxyStopService()
        }
        running = false
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        try { bridge.close() } catch (_: Exception) {}
    }

    private fun stopTunnel() {
        stopRequested = true
        expiryRunnable?.let { mainHandler.removeCallbacks(it) }
        expiryRunnable = null
        cleanupTunnel()
        updateNotification("Go VPN disconnected")
        broadcastStatus("disconnected", "VPN disconnected")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun notification(text: String): Notification {
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
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(text))
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
        stopRequested = true
        worker.execute { stopTunnel() }
        super.onRevoke()
    }

    override fun onDestroy() {
        stopRequested = true
        expiryRunnable?.let { mainHandler.removeCallbacks(it) }
        expiryRunnable = null
        worker.execute { cleanupTunnel() }
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
