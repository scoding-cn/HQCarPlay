package com.shilapi.xcertplay.network

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pGroup
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.HandlerThread
import android.os.Looper
import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** How a phone joins the diagnostic Wi-Fi Direct group. */
data class DiagnosticP2pCredentials(
    val ssid: String,
    val passphrase: String,
    /** True when the group already existed (wireless CarPlay owns it) and is left untouched. */
    val reused: Boolean,
)

/** The nearby Wi-Fi permission the driver has to grant before a group can be created. */
class DiagnosticP2pPermissionException : IOException("The nearby Wi-Fi permission is not granted")

/** The framework refused to create a group, typically because another app holds the radio. */
class DiagnosticP2pUnavailableException(val reason: Int) : IOException("Wi-Fi Direct refused the group: $reason")

/**
 * A Wi-Fi Direct group that exists only so a phone can read the diagnostic report.
 *
 * The car is the group owner, so the phone reaches the report server on the car's own interface.
 * No access point is in between, which is what defeats the isolated Wi-Fi the head unit offers.
 *
 * A group that wireless CarPlay already runs is reused and never removed, because removing it
 * drops that running session. Only a group this instance created is removed on [close].
 */
class DiagnosticP2pGroup(
    context: Context,
    private val diagnostic: (String) -> Unit = {},
) : Closeable {
    private val appContext = context.applicationContext

    // A head unit without the Wi-Fi Direct service fails here, inside start(), so the page can
    // report it like any other refusal instead of facing a throw out of the constructor.
    private val manager: WifiP2pManager by lazy {
        (appContext.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager)
            ?: throw DiagnosticP2pUnavailableException(WifiP2pManager.ERROR)
    }
    private val stateLock = Any()
    private var closed = false
    private var started = false
    private var thread: HandlerThread? = null
    private var channel: WifiP2pManager.Channel? = null
    private var created = false

    /**
     * Creates or adopts a group. Never call on the main thread: `requestGroupInfo` and `createGroup`
     * answer on the handler thread this method starts, and the caller blocks until they do.
     */
    fun start(timeoutMillis: Long): DiagnosticP2pCredentials {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "DiagnosticP2pGroup.start must not run on the main thread"
        }
        require(timeoutMillis > 0) { "timeoutMillis must be positive" }
        synchronized(stateLock) {
            check(!closed) { "DiagnosticP2pGroup is closed" }
            check(!started) { "DiagnosticP2pGroup has already started" }
            started = true
        }
        ensurePermission()

        val handlerThread = HandlerThread("diplay-diagnostic-p2p").apply { start() }
        thread = handlerThread
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val p2pChannel = manager.initialize(appContext, handlerThread.looper) {
            // The listener carries no reason; losing the channel means nothing answers any more.
            diagnostic("Wi-Fi Direct channel disconnected")
        }
        channel = p2pChannel

        adoptExisting(p2pChannel, deadline)?.let { group ->
            diagnostic("Wi-Fi Direct group adopted ssid=${group.networkName}")
            return DiagnosticP2pCredentials(
                ssid = requireNotNull(group.networkName) { "The existing Wi-Fi Direct group has no name" },
                passphrase = group.passphrase.orEmpty(),
                reused = true,
            )
        }

        createGroup(p2pChannel, deadline)
        synchronized(stateLock) { created = true }
        val group = awaitGroup(p2pChannel, deadline)
        val ssid = requireNotNull(group.networkName) { "The car did not name the Wi-Fi Direct group" }
        diagnostic("Wi-Fi Direct group created ssid=$ssid")
        return DiagnosticP2pCredentials(ssid, group.passphrase.orEmpty(), reused = false)
    }

    override fun close() {
        val handlerThread: HandlerThread
        val groupChannel: WifiP2pManager.Channel
        val owned: Boolean
        synchronized(stateLock) {
            if (closed) return
            closed = true
            handlerThread = thread ?: return
            groupChannel = channel ?: return
            owned = created
        }
        if (owned) {
            val removed = CountDownLatch(1)
            manager.removeGroup(groupChannel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() = removed.countDown()
                override fun onFailure(reason: Int) {
                    diagnostic("Wi-Fi Direct group removal failed reason=$reason")
                    removed.countDown()
                }
            })
            // A group left behind keeps the radio busy for the next CarPlay start; a stuck
            // removal is better reported than waited on forever.
            if (!removed.await(REMOVE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                diagnostic("Wi-Fi Direct group removal timed out")
            }
        }
        handlerThread.quitSafely()
    }

    private fun ensurePermission() {
        if (appContext.checkSelfPermission(nearbyWifiPermission()) != PackageManager.PERMISSION_GRANTED) {
            throw DiagnosticP2pPermissionException()
        }
    }

    private fun nearbyWifiPermission(): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) Manifest.permission.NEARBY_WIFI_DEVICES
        else Manifest.permission.ACCESS_FINE_LOCATION

    /**
     * Returns the group that is already running, or null when there is none. A framework that never
     * answers is treated as no group: creating one then reports the real reason.
     */
    private fun adoptExisting(channel: WifiP2pManager.Channel, deadline: Long): WifiP2pGroup? {
        val answer = GroupAnswer()
        manager.requestGroupInfo(channel, answer)
        return if (answer.await(deadline)) answer.group else null
    }

    private fun createGroup(channel: WifiP2pManager.Channel, deadline: Long) {
        val answer = CreateAnswer()
        // API 29 with a null config asks for system-generated credentials and no persistent group;
        // the older two-argument overload would leave a remembered group behind.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            manager.createGroup(channel, null as WifiP2pConfig?, answer)
        } else {
            manager.createGroup(channel, answer)
        }
        if (!answer.await(deadline)) throw IOException("Wi-Fi Direct group creation timed out")
        if (!answer.succeeded) throw DiagnosticP2pUnavailableException(answer.reason)
    }

    private fun awaitGroup(channel: WifiP2pManager.Channel, deadline: Long): WifiP2pGroup {
        while (true) {
            val group = adoptExisting(channel, deadline)
            if (group != null && group.isGroupOwner) return group
            if (System.nanoTime() >= deadline) throw IOException("The Wi-Fi Direct group did not appear")
            // The interface and its address settle a moment after the group is reported.
            Thread.sleep(GROUP_POLL_MILLIS)
        }
    }

    private abstract class Answer : WifiP2pManager.ActionListener {
        private val latch = CountDownLatch(1)
        @Volatile var succeeded = false
        @Volatile var reason = WifiP2pManager.ERROR

        override fun onSuccess() {
            succeeded = true
            latch.countDown()
        }

        override fun onFailure(reason: Int) {
            this.reason = reason
            latch.countDown()
        }

        fun await(deadline: Long): Boolean =
            latch.await(maxOf(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)
    }

    private class CreateAnswer : Answer()

    private class GroupAnswer : WifiP2pManager.GroupInfoListener {
        private val latch = CountDownLatch(1)
        @Volatile var group: WifiP2pGroup? = null

        override fun onGroupInfoAvailable(group: WifiP2pGroup?) {
            this.group = group
            latch.countDown()
        }

        fun await(deadline: Long): Boolean =
            latch.await(maxOf(0L, deadline - System.nanoTime()), TimeUnit.NANOSECONDS)
    }

    private companion object {
        const val GROUP_POLL_MILLIS = 300L
        const val REMOVE_TIMEOUT_SECONDS = 5L
    }
}
