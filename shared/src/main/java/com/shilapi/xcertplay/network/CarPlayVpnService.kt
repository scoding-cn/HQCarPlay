package com.shilapi.xcertplay.network

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import com.shilapi.xcertplay.airplay.AirPlayListenerIdentity
import com.shilapi.xcertplay.airplay.AirPlayTcpAccepted
import com.shilapi.xcertplay.airplay.isInternalAirPlayPeer
import com.shilapi.xcertplay.airplay.AirPlayConfig
import com.shilapi.xcertplay.airplay.AirPlayIdentity
import com.shilapi.xcertplay.airplay.AirPlayMediaHandler
import com.shilapi.xcertplay.airplay.AirPlaySession
import com.shilapi.xcertplay.airplay.AirPlaySessionListener
import com.shilapi.xcertplay.airplay.PairingStore
import com.shilapi.xcertplay.mfi.MfiAuthenticator
import com.shilapi.xcertplay.transport.NcmUsbBridge
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Hosts the AirPlay TCP listener for both NCM/VPN and local-only Wi-Fi transports.
 *
 * The wired path also owns the Android VPN tunnel and NCM IPv6 bridge. VPN consent is requested
 * with [prepare] before binding.
 */
class CarPlayVpnService : VpnService() {
    inner class LocalBinder : Binder() {
        val service: CarPlayVpnService get() = this@CarPlayVpnService
    }

    sealed class AttachResult {
        data object Started : AttachResult()
        data object AlreadyStarted : AttachResult()
        /** Existing TUN reused; NCM bridge swapped to the new NCM without re-establishing VPN. */
        data object Reused : AttachResult()
        data class Failed(val message: String) : AttachResult()
    }

    private data class AirPlayAttachment(
        val address: InetAddress,
        val config: AirPlayConfig,
        val identity: AirPlayIdentity,
        val pairings: PairingStore,
        val mfi: MfiAuthenticator?,
        val listener: AirPlaySessionListener,
        val media: AirPlayMediaHandler,
        val additionalAddresses: List<InetAddress> = emptyList(),
        val listenerIdentity: AirPlayListenerIdentity? = null,
    )

    private val binder = LocalBinder()
    private val active = AtomicBoolean(false)
    private val sessionsLock = Any()
    private val sessions = mutableSetOf<AirPlaySession>()
    @Volatile private var attachment: AirPlayAttachment? = null
    private var serverSocket: ServerSocket? = null
    private var additionalServers: List<ServerSocket> = emptyList()
    @Volatile private var bridge: Ipv6NcmBridge? = null
    @Volatile private var lwipBridge: LwipNcmBridge? = null
    private var tun: ParcelFileDescriptor? = null
    private var attachGeneration = 0

    /** The exception chain behind the latest [AttachResult.Failed], for the diagnostic log. */
    @Volatile var lastAttachFailure: String? = null
        private set

    override fun onBind(intent: Intent?): IBinder = binder

    @Synchronized
    fun attach(
        ncm: NcmUsbBridge,
        linkLocal: String,
        hostMac: ByteArray,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: MfiAuthenticator?,
        listener: AirPlaySessionListener,
        media: AirPlayMediaHandler,
    ): AttachResult {
        // 上一次尝试的 TUN 若仍然打开，则复用而不重新 establish，避免 netd 的 fwmark 规则泄漏。
        // detach() 只置 active=false 并保留 tun，因此这里检查 tun，而不是 active。
        var reuseTun = false
        val existingTun = tun
        if (existingTun != null) {
            val canReuse = if (active.get()) {
                attachment?.address?.hostAddress == linkLocal
            } else {
                true
            }
            if (canReuse) {
                reuseTun = true
                runCatching { listener.onDebugLog("wired VPN TUN reused (no re-establish, fwmark rule preserved)") }
            } else {
                Log.i(TAG, "replacing stale NCM/VPN attachment (TUN not reusable)")
                existingTun.close()
                tun = null
            }
        }
        if (active.get()) {
            Log.i(TAG, "replacing stale NCM/VPN attachment")
            releaseLocked()
        }
        active.set(true)
        val generation = ++attachGeneration
        return try {
            val address = InetAddress.getByName(linkLocal)
            if (address !is Inet6Address || !address.isLinkLocalAddress) {
                throw IllegalArgumentException("linkLocal must be a link-local IPv6 literal")
            }
            require(hostMac.size == 6) { "hostMac must be 6 bytes" }

            val tunFd = if (reuseTun) {
                existingTun!!
            } else {
                Builder()
                    .addAddress(linkLocal, LINK_PREFIX)
                    .addRoute(LINK_LOCAL_ROUTE, LINK_ROUTE_PREFIX)
                    .setSession(SESSION_NAME)
                    .setMtu(TUN_MTU)
                    .setBlocking(true)
                    // An empty app list routes every UID through this VPN. Scope it before establish;
                    // rejection must reach the existing attachment cleanup, never an unscoped retry.
                    .addAllowedApplication(packageName)
                    .establish()
                    ?: throw IOException("VpnService.establish returned null")
            }
            tun = tunFd

            val ipv6Bridge = Ipv6NcmBridge(
                ncm = ncm,
                tun = tunFd,
                hostMac = hostMac,
                hostLinkLocal = linkLocal,
                onDebugLog = { line -> runCatching { listener.onDebugLog(line) } },
                onError = { error -> onTransportError(generation, listener, error) },
            )
            ipv6Bridge.start()
            bridge = ipv6Bridge

            startAirPlayServer(
                generation,
                AirPlayAttachment(scopedToTunnel(address, listener), config, identity, pairings, mfi, listener, media),
            )
            boundPort()?.let { port ->
                runCatching { listener.onDebugLog("wired airplay listen kernel-check: ${verifyTcp6Listen(port)}") }
            }
            // Issue #148：仅安装单播 fe80::/10 路由时，JmDNS 组播无法穿过 TUN，
            // 在包层以内播单播应答 iPhone 的 mDNS 查询。best-effort，失败不影响已成功的 attach。
            runCatching {
                ipv6Bridge.mdnsResponder = WiredMdnsResponder(
                    deviceName = config.deviceName,
                    hostLinkLocal = linkLocal,
                    airPlayPort = boundPort() ?: config.port,
                    txtRecords = CarPlayBonjourProtocol.airPlayTxtRecords(config, identity),
                )
                listener.onDebugLog(
                    "wired mdns unicast responder armed on $linkLocal port=${boundPort() ?: config.port}",
                )
            }.onFailure { error ->
                Log.w(TAG, "wired mDNS unicast responder setup failed", error)
                runCatching { listener.onDebugLog("wired mDNS unicast responder setup failed: ${error.message}") }
            }
            if (reuseTun) AttachResult.Reused else AttachResult.Started
        } catch (error: Exception) {
            releaseLocked()
            lastAttachFailure = attachFailure(error)
            AttachResult.Failed(error.message ?: error.javaClass.simpleName)
        }
    }

    /**
     * Starts the AirPlay listener on loopback (127.0.0.1) and relays traffic to/from USB CDC-NCM
     * using the userspace lwIP protocol stack. No VpnService establish or Linux TUN required.
     */
    @Synchronized
    fun attachUserspace(
        ncm: NcmUsbBridge,
        linkLocal: String,
        hostMac: ByteArray,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: MfiAuthenticator?,
        listener: AirPlaySessionListener,
        media: AirPlayMediaHandler,
    ): AttachResult {
        if (active.get()) {
            Log.i(TAG, "replacing stale attachment for userspace lwIP")
            releaseLocked()
        }
        active.set(true)
        val generation = ++attachGeneration
        lastAttachFailure = null
        var attachStage = "Userspace lwIP setup"
        return try {
            require(hostMac.size == 6) { "hostMac must be 6 bytes" }

            val lwip = LwipNcmBridge(
                ncm = ncm,
                hostMac = hostMac,
                hostLinkLocal = linkLocal,
                onDebugLog = { line -> runCatching { listener.onDebugLog(line) } },
                onError = { error -> onTransportError(generation, listener, error) },
            )
            attachStage = "NCM lwIP bridge startup"
            lwip.start()
            lwipBridge = lwip
            runCatching { listener.onDebugLog("wired userspace lwIP bridge started") }

            attachStage = "AirPlay loopback listener bind"
            val loopback = InetAddress.getByName("127.0.0.1")
            val wrappedListener = object : AirPlaySessionListener by listener {
                override fun onPortBound(port: Int, isTcp: Boolean) {
                    lwip.registerPort(port, isTcp)
                    listener.onPortBound(port, isTcp)
                }
            }

            startAirPlayServer(
                generation,
                AirPlayAttachment(loopback, config, identity, pairings, mfi, wrappedListener, media),
            )
            val bound = boundPort() ?: config.port
            lwip.registerPort(bound, isTcp = true)
            runCatching { listener.onDebugLog("wired AirPlay listener bound on 127.0.0.1 port=$bound (lwIP userspace)") }

            attachStage = "wired mDNS unicast responder"
            runCatching {
                lwip.mdnsResponder = WiredMdnsResponder(
                    deviceName = config.deviceName,
                    hostLinkLocal = linkLocal,
                    airPlayPort = bound,
                    txtRecords = CarPlayBonjourProtocol.airPlayTxtRecords(config, identity),
                )
                runCatching {
                    listener.onDebugLog("wired mDNS unicast responder installed on lwIP bridge port=$bound")
                }
            }.onFailure { error ->
                Log.w(TAG, "wired mDNS unicast responder unavailable", error)
                runCatching { listener.onDebugLog("wired mDNS responder failed: ${error.message}") }
            }

            AttachResult.Started
        } catch (error: Exception) {
            lastAttachFailure = "$attachStage: ${attachFailure(error)}"
            Log.e(TAG, "wired userspace lwIP attach failed: $lastAttachFailure", error)
            runCatching { listener.onDebugLog("wired userspace lwIP attach failed: $lastAttachFailure") }
            releaseLocked()
            AttachResult.Failed(error.message ?: error.javaClass.simpleName)
        }
    }

    /**
     * Starts the AirPlay listener on the local-only Wi-Fi AP address without establishing a VPN or
     * NCM bridge.
     */
    @Synchronized
    fun attachWireless(
        bindAddress: InetAddress,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: MfiAuthenticator?,
        listener: AirPlaySessionListener,
        media: AirPlayMediaHandler,
        additionalBindAddresses: List<InetAddress> = emptyList(),
        listenerIdentity: AirPlayListenerIdentity? = null,
    ): AttachResult {
        if (active.get()) {
            Log.i(TAG, "replacing stale local-only Wi-Fi attachment")
            releaseLocked()
        }
        active.set(true)
        val generation = ++attachGeneration
        return try {
            startAirPlayServer(
                generation,
                AirPlayAttachment(bindAddress, config, identity, pairings, mfi, listener, media,
                    additionalBindAddresses, listenerIdentity),
            )
            AttachResult.Started
        } catch (error: Exception) {
            releaseLocked()
            lastAttachFailure = attachFailure(error)
            AttachResult.Failed(error.message ?: error.javaClass.simpleName)
        }
    }

    /** Releases the active AirPlay listener and whichever VPN/NCM transport resources are active. */
    @Synchronized
    fun detach() {
        releaseLocked()
    }

    @Synchronized
    fun detachWireless(owner: AirPlayListenerIdentity) {
        if (attachment?.listenerIdentity === owner) releaseLocked()
    }

    fun isAttached(): Boolean = active.get() && attachment != null

    /** 让有线桥立即再发一次无条件邻居通告，用于 iAP2 控制通道就绪或重连时机。 */
    fun sendUnsolicitedNeighborAdvertisement(force: Boolean = false) {
        bridge?.sendUnsolicitedNeighborAdvertisement(force)
        lwipBridge?.sendUnsolicitedNeighborAdvertisement(force)
    }

    /** Port the AirPlay listener actually bound, which may differ from the configured port. */
    fun boundPort(): Int? = attachment?.config?.port

    /**
     * Issue #133: Java 的 bind() 成功并不能证明内核真的注册了监听 socket（netd/VPN 卡死会撒谎）。
     * /proc/net/tcp6 全局可读：确认目标端口确实存在 LISTEN socket，让下一份诊断报告能区分
     * "监听器未注册" 与 "SYN 在 TUN 入口到 TCP 之间丢失"。
     */
    private fun verifyTcp6Listen(port: Int): String {
        val portHex = port.toString(16).uppercase().padStart(4, '0')
        return try {
            var found = false
            java.io.File("/proc/net/tcp6").bufferedReader().use { reader ->
                var line = reader.readLine()
                while (line != null) {
                    // 列：sl | local_address | rem_address | st | ...
                    val fields = line.trim().split(Regex("\\s+"))
                    if (fields.size >= 4 &&
                        fields[1].endsWith(":$portHex", ignoreCase = true) &&
                        fields[3].equals("0A", ignoreCase = true)
                    ) {
                        found = true
                        break
                    }
                    line = reader.readLine()
                }
            }
            if (found) {
                "kernel LISTEN present on tcp6 port $port"
            } else {
                "WARNING: no LISTEN socket for port $port in /proc/net/tcp6 " +
                    "(bind succeeded but the kernel never registered it; reboot the head unit)"
            }
        } catch (error: Exception) {
            "/proc/net/tcp6 unreadable: ${error.message}"
        }
    }

    /**
     * 诊断快照：AirPlay 端口上的 TCP 状态。用户态模式读取 lwIP 内部快照，
     * VPN 模式解析 /proc/net/tcp6 内核表。用于区分 "SYN 从未到达 TCP 栈" 与
     * "SYN 已到达但 SYN-ACK 回程丢失" 这两类故障（legacy issue #155/#123）。
     */
    fun tunTcpSnapshot(): String {
        val port = boundPort() ?: return "tun tcp6 snapshot unavailable: no bound port"
        val portHex = port.toString(16).uppercase().padStart(4, '0')
        val injected = lwipBridge?.injectedTcpPackets?.get() ?: bridge?.injectedTcpPackets?.get() ?: -1
        if (lwipBridge != null) {
            val lwipSnap = lwipBridge?.tcpSnapshot() ?: "none"
            return "userspace lwIP tcp port=$port injectedTcp=$injected $lwipSnap"
        }
        var listen = 0
        var synRecv = 0
        var established = 0
        var other = 0
        runCatching {
            java.io.File("/proc/net/tcp6").bufferedReader().use { reader ->
                var line = reader.readLine()
                while (line != null) {
                    // 列：sl | local_address | rem_address | st | ...
                    // st：01=ESTABLISHED 03=SYN_RECV 0A=LISTEN
                    val fields = line.trim().split(Regex("\\s+"))
                    if (fields.size >= 4 &&
                        fields[1].endsWith(":$portHex", ignoreCase = true)
                    ) {
                        when {
                            fields[3].equals("0A", ignoreCase = true) -> listen++
                            fields[3].equals("03", ignoreCase = true) -> synRecv++
                            fields[3].equals("01", ignoreCase = true) -> established++
                            else -> other++
                        }
                    }
                    line = reader.readLine()
                }
            }
        }
        return "tun tcp6 port=$port listen=$listen synRecv=$synRecv " +
            "established=$established other=$other injectedTcp=$injected"
    }

    override fun onDestroy() {
        releaseLocked()
        // releaseLocked 会保留 TUN 供复用；Service 真正销毁时才关闭它。
        tun?.close()
        tun = null
        super.onDestroy()
    }

    /**
     * Linux rejects bind() to a link-local IPv6 address without a scope id (EINVAL). Android 8+
     * IoBridge.bind looks the scope up itself, but Android 7.x binds natively in
     * PlainSocketImpl.socketBind and never derives one, so the unscoped wired listener failed with
     * "Invalid argument". Scope it to the tunnel that owns the address on every version; when no
     * interface owns it, keep the unscoped address and the platform's own behavior.
     */
    private fun scopedToTunnel(address: Inet6Address, listener: AirPlaySessionListener): InetAddress {
        if (address.scopeId != 0) return address
        var interfaces = emptyList<TunnelCandidate>()
        repeat(TUN_LOOKUP_ATTEMPTS) { attempt ->
            if (attempt > 0) Thread.sleep(TUN_LOOKUP_DELAY_MILLIS)
            interfaces = tunnelCandidates()
            selectTunnelInterface(address, interfaces)?.let { owner ->
                runCatching { listener.onDebugLog("wired AirPlay listener scope iface=${owner.name} index=${owner.index}") }
                return Inet6Address.getByAddress(null, address.address, owner.index)
            }
        }
        val tunnels = interfaces.filter { it.name.startsWith("tun") }.joinToString(",") { it.name }.ifEmpty { "none" }
        runCatching { listener.onDebugLog("wired AirPlay listener scope iface=not_found tun=$tunnels; binding unscoped") }
        return address
    }

    private fun tunnelCandidates(): List<TunnelCandidate> = runCatching {
        NetworkInterface.getNetworkInterfaces()?.let { Collections.list(it) }.orEmpty().map { networkInterface ->
            TunnelCandidate(networkInterface.name, networkInterface.index, Collections.list(networkInterface.inetAddresses))
        }
    }.getOrDefault(emptyList())

    private fun startAirPlayServer(
        generation: Int,
        replacement: AirPlayAttachment,
    ) {
        val servers = if (replacement.additionalAddresses.isEmpty()) {
            listOf(AirPlayPortSelector.bind(replacement.address, replacement.config.port) { busy, bound ->
                Log.w(TAG, "AirPlay port $busy is in use; listening on $bound instead")
            })
        } else {
            AirPlayPortSelector.bindAll(listOf(replacement.address) + replacement.additionalAddresses,
                replacement.config.port) { busy, bound ->
                Log.w(TAG, "AirPlay port $busy is in use; listening on $bound instead")
            }
        }
        val server = servers.first()
        attachment = replacement.copy(config = replacement.config.copy(port = server.localPort))
        serverSocket = server
        additionalServers = servers.drop(1)
        servers.forEach { bound ->
            runCatching { replacement.listener.onDebugLog(
                "airplay listener ready family=${if (bound.inetAddress is Inet6Address) "IPv6" else "IPv4"} port=${bound.localPort}",
            ) }
            Thread(
                { acceptLoop(generation, bound) },
                "airplay-accept",
            ).apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun acceptLoop(
        generation: Int,
        server: ServerSocket,
    ) {
        try {
            while (active.get()) {
                val socket: Socket = server.accept()
                val acceptedAtNanos = System.nanoTime()
                Log.i(TAG, "airplay connection accepted from ${socket.remoteSocketAddress}")
                socket.tcpNoDelay = true
                socket.keepAlive = true
                socket.setSoLinger(true, 0)
                val session = synchronized(this) {
                    if (!active.get() || generation != attachGeneration ||
                        (serverSocket !== server && additionalServers.none { it === server })) {
                        socket.close()
                        return
                    }
                    val current = attachment
                    if (current == null) {
                        socket.close()
                        return
                    }
                    val internalPeer = isInternalAirPlayPeer(socket.inetAddress, socket.localAddress)
                    current.listenerIdentity?.let { owner ->
                        current.listener.onTcpAccepted(AirPlayTcpAccepted(
                            owner, internalPeer, acceptedAtNanos,
                        ))
                    }
                    runCatching { current.listener.onDebugLog(
                        "airplay TCP accepted family=${if (socket.inetAddress is Inet6Address) "IPv6" else "IPv4"}",
                    ) }
                    AirPlaySession(
                        socket = socket,
                        config = current.config,
                        identity = current.identity,
                        pairings = current.pairings,
                        mfi = current.mfi,
                        listener = object : AirPlaySessionListener by current.listener {
                            override fun onSessionActive(session: AirPlaySession) {
                                if (current.listenerIdentity == null || !internalPeer) current.listener.onSessionActive(session)
                            }

                            override fun onRemoteControlMessage(
                                session: AirPlaySession,
                                streamId: Long,
                                message: Map<String, Any?>,
                            ) {
                                current.listener.onRemoteControlMessage(session, streamId, message)
                            }

                            override fun onVideoPlaybackUiRequested(session: AirPlaySession) {
                                current.listener.onVideoPlaybackUiRequested(session)
                            }

                            override fun onSessionEnded(session: AirPlaySession) {
                                removeSession(session)
                                if (current.listenerIdentity == null || !internalPeer) current.listener.onSessionEnded(session)
                            }
                        },
                        media = current.media,
                    ).also(::addSession)
                }
                session.start()
            }
        } catch (error: IOException) {
            if (active.get()) {
                attachment?.listener?.let { onTransportError(generation, it, error) }
            }
        }
    }

    private fun addSession(session: AirPlaySession) {
        synchronized(sessionsLock) { sessions.add(session) }
    }

    private fun removeSession(session: AirPlaySession?) {
        if (session == null) return
        synchronized(sessionsLock) { sessions.remove(session) }
    }

    private fun closeSessionsLocked() {
        synchronized(sessionsLock) {
            sessions.toList().forEach { session ->
                try {
                    session.close()
                } catch (error: Exception) {
                    Log.w(TAG, "AirPlay session replacement failed", error)
                }
            }
            sessions.clear()
        }
    }

    private fun onTransportError(
        generation: Int,
        listener: AirPlaySessionListener,
        error: Throwable,
    ) {
        val message = error.message ?: error.javaClass.simpleName
        Log.e(TAG, "CarPlay transport stopped: $message", error)
        Thread(
            {
                val releasedGeneration = synchronized(this) {
                    if (generation != attachGeneration) return@Thread
                    releaseLocked()
                    attachGeneration
                }
                listener.onTransportError(message)
                synchronized(this) {
                    if (attachGeneration == releasedGeneration && !active.get()) stopSelf()
                }
            },
            "airplay-teardown",
        ).apply {
            isDaemon = true
            start()
        }
    }

    /** Caller must hold this service's monitor. Closes only resources active for this attachment. */
    private fun releaseLocked() {
        attachGeneration += 1
        active.set(false)
        attachment = null
        serverSocket?.close()
        serverSocket = null
        additionalServers.forEach { it.close() }
        additionalServers = emptyList()
        closeSessionsLocked()
        bridge?.close()
        bridge = null
        lwipBridge?.close()
        lwipBridge = null
        // 刻意不关闭 TUN：保留 fd 供下一次 attach 复用，避免反复 establish 泄漏 netd fwmark 规则。
        // 真正的销毁路径在 onDestroy()。
    }

    companion object {
        private const val TAG = "xcertplay-usb"
        private const val LINK_PREFIX = 64
        private const val LINK_LOCAL_ROUTE = "fe80::"
        /** 路由加宽到 fe80::/10：iPhone 的 EUI-64 链路本地地址不在 fe80::/64 内（issue #148/#150）。 */
        private const val LINK_ROUTE_PREFIX = 10
        private const val SESSION_NAME = "xcertplay CarPlay"
        private const val TUN_MTU = 1500
        private const val TUN_LOOKUP_ATTEMPTS = 10
        private const val TUN_LOOKUP_DELAY_MILLIS = 50L

        internal data class TunnelCandidate(val name: String, val index: Int, val addresses: List<InetAddress>)

        /**
         * Picks the interface that owns [address]. A tun interface wins when another interface
         * happens to carry the same link-local address.
         */
        internal fun selectTunnelInterface(address: Inet6Address, interfaces: List<TunnelCandidate>): TunnelCandidate? {
            val owners = interfaces.filter { candidate ->
                candidate.index > 0 && candidate.addresses.any { owned ->
                    owned is Inet6Address && owned.address.contentEquals(address.address)
                }
            }
            return owners.firstOrNull { it.name.startsWith("tun") } ?: owners.firstOrNull()
        }

        /** Returns the VPN consent intent, or null when consent is already granted. */
        fun prepare(context: Context): Intent? = VpnService.prepare(context)

        /**
         * Android 7.1 reported only "Invalid argument" when establish failed (#557); name the
         * exception chain and the frame that threw, so the rejected VPN setting can be identified.
         */
        internal fun attachFailure(error: Throwable): String {
            val chain = generateSequence(error) { it.cause }.take(4).joinToString(" <- ") { failure ->
                "${failure.javaClass.simpleName}: ${failure.message ?: "no message"}"
            }
            val origin = error.stackTrace.firstOrNull()
                ?.let { " at ${it.className.substringAfterLast('.')}.${it.methodName}" }.orEmpty()
            return chain + origin
        }
    }
}
