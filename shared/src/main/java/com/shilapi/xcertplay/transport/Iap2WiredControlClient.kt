package com.shilapi.xcertplay.transport

import com.shilapi.xcertplay.iap2.message.Iap2CarPlayMessages
import com.shilapi.xcertplay.iap2.message.Iap2ControlMessages
import com.shilapi.xcertplay.iap2.session.Iap2Session
import com.shilapi.xcertplay.iap2.wire.Iap2Frame
import com.shilapi.xcertplay.mfi.Iap2MfiAuthenticationClient
import java.net.Inet6Address
import java.net.InetAddress

/**
 * The wired LIVI control sequence after a CSM channel is ready:
 * Identification, MFi, power announcement, five update subscriptions, then CarPlay availability.
 *
 * The caller retains ownership of [session]. While [run] is active it is the only receiver and
 * forwards each non-availability CSM frame to [onIncoming]; it neither opens NCM nor implements
 * an AirPlay receiver.
 */
class Iap2WiredControlClient(
    private val session: Iap2Session,
    private val mfi: Iap2MfiAuthenticationClient,
    private val peerSilentResetMillis: Long = PEER_SILENT_RESET_MILLIS,
    private val peerIdleDiagnosticMillis: Long = PEER_IDLE_DIAGNOSTIC_MILLIS,
) {
    fun run(
        identification: Iap2IdentificationConfig,
        endpoint: Iap2WiredCarPlayEndpoint,
        availableCurrentMilliAmps: Int,
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
        locationProvider: Iap2LocationProvider? = null,
        vehicleStatusProvider: VehicleStatusProvider? = null,
        onIncoming: (Iap2Frame) -> Unit = {},
        onProgress: (String) -> Unit = {},
        /**
         * 对端静默是否允许拆链的媒介信号（legacy issue #134）：iAP2 安静且该回调报告最近
         * 没有 AirPlay 媒体时才允许复位，否则继续保链。null 表示调用方没有活跃度信号，
         * 保持"仅凭 iAP2 静默即复位"的行为。
         */
        airPlayDataRecent: (() -> Boolean)? = null,
        startSessionAgain: () -> StartAgain = { StartAgain.DONE },
    ): Iap2WiredControlResult {
        require(availableCurrentMilliAmps in 0..0xffff) {
            "availableCurrentMilliAmps must be in 0..65535"
        }
        require(timeoutMillis == NO_TIMEOUT_MILLIS || timeoutMillis in 1..MAX_TIMEOUT_MILLIS) {
            "timeoutMillis must be in 1..$MAX_TIMEOUT_MILLIS or NO_TIMEOUT_MILLIS"
        }

        val deadlineNanos = Iap2ControlDeadline(timeoutMillis)
        val identified = identification.withVehicleStatusFrom(vehicleStatusProvider)
        if (identified.vehicleStatusEnabled != identification.vehicleStatusEnabled) {
            onProgress("iap2 no battery reading: not declaring an electric vehicle")
        }
        Iap2IdentificationClient(session).identify(identified, requireRemaining(deadlineNanos), onProgress)
        onProgress("iap2 identification accepted")
        var stage = Iap2WiredControlStage.IDENTIFIED
        mfi.run(session, requireRemaining(deadlineNanos), onProgress)
        stage = Iap2WiredControlStage.AUTHENTICATED
        onProgress("iap2 authentication accepted")
        deadlineNanos.authenticated()

        send(powerSourceUpdate(availableCurrentMilliAmps), deadlineNanos)
        for (subscription in subscriptions()) send(subscription, deadlineNanos)
        stage = Iap2WiredControlStage.SUBSCRIBED
        onProgress("iap2 power/subscriptions sent availableCurrentMa=$availableCurrentMilliAmps")

        var forwardedFrames = 0
        val rxLog = Iap2RxLog()
        var carPlayStartSessions = 0
        var startAgainDecided = false
        val loopStartNanos = System.nanoTime()
        /** 每次运行只报一次"媒介仍活跃所以保链"，避免静默期间刷屏。 */
        var keptLinkAfterSilence = false
        // issue #84/#61：此前没有死链检测，iPhone 静默后 recv 一直超时、循环空转。
        val silenceMonitor = Iap2PeerSilenceMonitor(peerSilentResetMillis, peerIdleDiagnosticMillis)
        // 只有最初的 CarPlay availability 握手设时限，运行期控制通道保持常开。
        val startupDeadlineNanos = System.nanoTime() + STARTUP_AVAILABILITY_TIMEOUT_MILLIS * NANOS_PER_MILLISECOND
        val location = Iap2LocationReporter(locationProvider, onProgress)
        val vehicleStatus = Iap2VehicleStatusReporter(vehicleStatusProvider, onProgress)
        try {
            while (true) {
                val remaining = remainingMillis(deadlineNanos)
                if (remaining == 0L) {
                    return Iap2WiredControlResult(Iap2WiredControlTerminal.TIMED_OUT, stage, forwardedFrames, carPlayStartSessions)
                }
                location.tick { send(it, deadlineNanos) }
                vehicleStatus.tick { send(it, deadlineNanos) }
                var startAgainPending = false
                if (!startAgainDecided && stage == Iap2WiredControlStage.CARPLAY_START_SENT) {
                    when (startSessionAgain()) {
                        StartAgain.WAIT -> startAgainPending = true
                        StartAgain.DONE -> startAgainDecided = true
                        StartAgain.SEND -> {
                            startAgainDecided = true
                            send(carPlayStartSession(endpoint), deadlineNanos)
                            carPlayStartSessions++
                            onProgress(START_SESSION_AGAIN_PROGRESS)
                        }
                    }
                }
                val startupRemaining = if (carPlayStartSessions == 0) {
                    ((startupDeadlineNanos - System.nanoTime()) / NANOS_PER_MILLISECOND).coerceAtLeast(0L)
                } else remaining
                if (startupRemaining == 0L) {
                    onProgress("iap2 wired startup timed out waiting for CarPlay availability")
                    return Iap2WiredControlResult(Iap2WiredControlTerminal.TIMED_OUT, stage, forwardedFrames, carPlayStartSessions)
                }
                // 三个上限取最小：整体 deadline、启动期 60s availability 窗口、HOLD 期 500ms 状态机探测
                val pollTimeout = vehicleStatus.pollTimeout(
                    location.pollTimeout(minOf(remaining, startupRemaining)),
                ).let { base ->
                    if (startAgainPending) minOf(base, START_AGAIN_POLL_MILLIS) else base
                }
                val incoming = session.recv(pollTimeout)
                if (incoming == null) {
                    if (session.isClosed) {
                        return Iap2WiredControlResult(
                            Iap2WiredControlTerminal.CHANNEL_CLOSED,
                            stage,
                            forwardedFrames,
                            carPlayStartSessions,
                        )
                    }
                    if (remainingMillis(deadlineNanos) == 0L) {
                        return Iap2WiredControlResult(
                            Iap2WiredControlTerminal.TIMED_OUT,
                            stage,
                            forwardedFrames,
                            carPlayStartSessions,
                        )
                    }

                    // 无物理拔插的 USB 重连场景：iPhone 认为会话已宣告过，往往不再补发 0x4300。
                    // 宽限期（2.5 s）过后主动发送 0x4301 触发 iPhone 侧的 AirPlay TCP 建连。
                    if (carPlayStartSessions == 0 &&
                        (System.nanoTime() - loopStartNanos) >= PROACTIVE_START_SESSION_DELAY_MILLIS * NANOS_PER_MILLISECOND
                    ) {
                        onProgress("iap2 availability wait grace period elapsed (2.5s); proactively sending carplay-start-session (0x4301)")
                        send(carPlayStartSession(endpoint), deadlineNanos)
                        stage = Iap2WiredControlStage.CARPLAY_START_SENT
                        carPlayStartSessions++
                        onProgress("iap2 tx=0x4301 carplay-start-session")
                    }

                    // issue #84/#61：把对端静默写进诊断日志，StartSession 之后长时间安静则重建链路。
                    silenceMonitor.diagnosticIfDue()?.let { onProgress(it) }
                    if (
                        carPlayStartSessions > 0 &&
                        shouldResetLinkOnPeerSilence(
                            peerSilent = silenceMonitor.shouldReset(),
                            airPlayDataRecent = airPlayDataRecent?.invoke(),
                        )
                    ) {
                        onProgress("iap2 wired peer silent for ${silenceMonitor.idleMillis()}ms; resetting link")
                        return Iap2WiredControlResult(
                            Iap2WiredControlTerminal.PEER_SILENT,
                            stage,
                            forwardedFrames,
                            carPlayStartSessions,
                        )
                    }
                    if (carPlayStartSessions > 0 && silenceMonitor.shouldReset() && !keptLinkAfterSilence) {
                        // 给下一份诊断报告留证据：这次复位是被有意压制的，以及保链期间控制通道实际静默了多久。
                        keptLinkAfterSilence = true
                        onProgress(
                            "iap2 wired peer silent for ${silenceMonitor.idleMillis()}ms " +
                                "but AirPlay media is still arriving; keeping the link",
                        )
                    }
                    continue
                }
                silenceMonitor.onFrameReceived()

                when (incoming.messageId) {
                    CARPLAY_AVAILABILITY -> {
                        onProgress("iap2 rx=0x4300 carplay-availability")
                        onProgress(carPlayAvailabilitySummary(incoming.payload))
                        // LIVI sends its wired answer on every availability notification; do not gate it on
                        // the phone's advertised availability boolean.
                        send(carPlayStartSession(endpoint), deadlineNanos)
                        stage = Iap2WiredControlStage.CARPLAY_START_SENT
                        carPlayStartSessions++
                        onProgress("iap2 tx=0x4301 carplay-start-session")
                    }

                    Iap2LocationMessages.START_LOCATION_INFORMATION, Iap2LocationMessages.STOP_LOCATION_INFORMATION -> {
                        location.handle(incoming) { send(it, deadlineNanos) }
                    }

                    Iap2VehicleStatus.START_VEHICLE_STATUS_UPDATES, Iap2VehicleStatus.STOP_VEHICLE_STATUS_UPDATES -> {
                        vehicleStatus.handle(incoming) { send(it, deadlineNanos) }
                    }

                    else -> {
                        rxLog.line(incoming.messageId)?.let(onProgress)
                        onIncoming(incoming)
                        forwardedFrames++
                    }
                }
            }
        } finally {
            locationProvider?.stop()
        }
    }

    private fun send(frame: Iap2Frame, deadlineNanos: Iap2ControlDeadline) {
        session.send(frame, requireRemaining(deadlineNanos))
    }

    /** Asked while a session is awaited after `carplay-start-session`; see WiredStartAgain. */
    enum class StartAgain { WAIT, SEND, DONE }

    companion object {
        const val NO_TIMEOUT_MILLIS = Long.MAX_VALUE
        const val START_SESSION_AGAIN_PROGRESS =
            "iap2 tx=0x4301 carplay-start-session again: no AirPlay connection since the USB network opened"
        private const val START_AGAIN_POLL_MILLIS = 500L
        private const val CARPLAY_AVAILABILITY = 0x4300
        private const val CARPLAY_START_SESSION = 0x4301
        private const val STARTUP_AVAILABILITY_TIMEOUT_MILLIS = 60_000L
        private const val PROACTIVE_START_SESSION_DELAY_MILLIS = 2_500L
        private const val DEFAULT_TIMEOUT_MILLIS = 60_000L
        private const val MAX_TIMEOUT_MILLIS = 24 * 60 * 60 * 1_000L
        private const val MAX_RECV_TIMEOUT_MILLIS = 5 * 60 * 1_000L
        private const val NANOS_PER_MILLISECOND = 1_000_000L
        /** 安静 iAP2 对端的诊断日志节奏（issue #84/#61，Fix 0）。 */
        private const val PEER_IDLE_DIAGNOSTIC_MILLIS = 30_000L
        /** StartSession 之后长时间安静：判定链路已死并重建（issue #84/#61，Fix 1）。 */
        private const val PEER_SILENT_RESET_MILLIS = 90_000L

        /** Exact LIVI wired PowerSourceUpdate encoding: current and the charge-if-powered flag. */
        fun powerSourceUpdate(availableCurrentMilliAmps: Int): Iap2Frame =
            Iap2ControlMessages.powerSourceUpdate(availableCurrentMilliAmps, charging = true)

        /** Exact five subscription requests emitted by LIVI's wired bring-up. */
        fun subscriptions(): List<Iap2Frame> = Iap2ControlMessages.subscriptions()

        /** Builds the wired-only CarPlayStartSession message; no NCM or AirPlay socket is opened. */
        fun carPlayStartSession(endpoint: Iap2WiredCarPlayEndpoint): Iap2Frame =
            Iap2CarPlayMessages.startSession(
                wiredIpv6Addresses = endpoint.ipv6Addresses,
                airPlayPort = endpoint.airPlayPort,
                deviceIdentifier = endpoint.deviceIdentifier,
                publicKey = endpoint.publicKey,
                sourceVersion = endpoint.sourceVersion,
            )

        fun carPlayAvailabilitySummary(payload: ByteArray): String {
            return try {
                val availability = Iap2CarPlayMessages.availability(payload).wired
                val available = availability?.available
                val transport = availability?.identifier
                "iap2 4300 wiredAvailable=$available usbTransport=${transport ?: "none"}"
            } catch (error: RuntimeException) {
                "iap2 4300 decode failed: ${error.message}"
            }
        }

        private fun requireRemaining(deadlineNanos: Iap2ControlDeadline): Long = remainingMillis(deadlineNanos).also {
            if (it == 0L) throw IphoneUsbException.TimedOut("Timed out during wired iAP2 control bring-up")
        }

        private fun remainingMillis(deadlineNanos: Iap2ControlDeadline): Long = deadlineNanos.remainingMillis()

    }
}

/** A configured wired AirPlay endpoint; configuration does not claim that either service is live. */
class Iap2WiredCarPlayEndpoint(
    ipv6Addresses: List<String>,
    val airPlayPort: Int,
    val publicKey: String,
    val sourceVersion: String,
    val deviceIdentifier: String? = null,
) {
    /** A stable copy so a caller cannot mutate a validated endpoint before it is encoded. */
    val ipv6Addresses: List<String> = ipv6Addresses.toList()

    init {
        require(ipv6Addresses.isNotEmpty()) { "At least one wired IPv6 address is required" }
        require(ipv6Addresses.all(::isIpv6Literal)) { "Every wired address must be an IPv6 text literal" }
        require(airPlayPort in 1..65535) { "airPlayPort must be in 1..65535" }
        require(publicKey.isNotEmpty()) { "publicKey is required and must not be empty" }
        require(sourceVersion.isNotEmpty()) { "sourceVersion is required and must not be empty" }
        require('\u0000' !in publicKey) { "publicKey must not contain U+0000" }
        require('\u0000' !in sourceVersion) { "sourceVersion must not contain U+0000" }
        deviceIdentifier?.let {
            require(it.isNotEmpty()) { "deviceIdentifier is optional, but must not be empty when provided" }
            require('\u0000' !in it) { "deviceIdentifier must not contain U+0000" }
        }
    }

    private companion object {
        fun isIpv6Literal(value: String): Boolean {
            if (value.contains('%') || '\u0000' in value || !value.contains(':')) return false
            return try {
                InetAddress.getByName(value) is Inet6Address
            } catch (_: Exception) {
                false
            }
        }
    }
}

enum class Iap2WiredControlStage {
    IDENTIFIED,
    AUTHENTICATED,
    SUBSCRIBED,
    CARPLAY_START_SENT,
}

enum class Iap2WiredControlTerminal { CHANNEL_CLOSED, TIMED_OUT, PEER_SILENT }

/** End state of the control loop only; it is not evidence of NCM or AirPlay availability. */
data class Iap2WiredControlResult(
    val terminal: Iap2WiredControlTerminal,
    val stage: Iap2WiredControlStage,
    val forwardedFrames: Int,
    val carPlayStartSessionsSent: Int,
)

/**
 * issue #134：判定 iAP2 静默是否允许复位有线链路。
 *
 * 只凭 iAP2 静默复位曾拆掉正在工作的会话：NTDA3 的 iPhone 会在视频持续播放的几分钟内
 * 停发 iAP2 帧，90 s 复位导致画面中断约一分钟。只有 AirPlay 媒体同样安静时才允许复位。
 * [airPlayDataRecent] 为 null 表示调用方没有活跃度信号，此时保持"静默即复位"的行为。
 */
internal fun shouldResetLinkOnPeerSilence(peerSilent: Boolean, airPlayDataRecent: Boolean?): Boolean =
    peerSilent && airPlayDataRecent != true
