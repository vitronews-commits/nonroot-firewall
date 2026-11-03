package com.nonroot.firewall

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/**
 * Experimental one-shot UDP exchange. Caller MUST perform app attribution and
 * policy checks first. Does not create a VPN, write TUN, or support TCP.
 *
 * This is deliberately synchronous: run it only on a worker thread.
 * A production relay needs persistent per-flow sockets and asynchronous receive.
 */
class UdpExchange(private val socketFactory: () -> DatagramSocket) {
    sealed class Outcome {
        data class Reply(val packet: ByteArray) : Outcome()
        object TimedOut : Outcome()
        object Rejected : Outcome()
    }

    fun exchange(
        request: UdpDatagram.Parsed,
        decision: PacketPolicy.Result,
        timeoutMs: Int = 1500
    ): Outcome {
        // Never create a socket until policy is positively ALLOW.
        if (decision != PacketPolicy.Result.ALLOW) return Outcome.Rejected
        if (timeoutMs !in 1..10_000 || request.destinationPort !in 1..65535 ||
            request.sourcePort !in 1..65535 || request.payload.size > 1472) return Outcome.Rejected
        val remote = try {
            val ip = InetAddress.getByName(request.destinationIp)
            if (ip.address.size != 4 || ip.hostAddress != request.destinationIp) return Outcome.Rejected
            InetSocketAddress(ip, request.destinationPort)
        } catch (_: Exception) {
            return Outcome.Rejected
        }
        return try {
            socketFactory().use { udp ->
                udp.soTimeout = timeoutMs
                udp.connect(remote)
                udp.send(DatagramPacket(request.payload, request.payload.size))
                val buffer = ByteArray(2048)
                val received = DatagramPacket(buffer, buffer.size)
                try {
                    udp.receive(received)
                } catch (_: SocketTimeoutException) {
                    return Outcome.TimedOut
                }
                val reply = UdpResponsePacket.build(
                    request, received.data.copyOfRange(received.offset, received.offset + received.length)
                ) ?: return Outcome.Rejected
                Outcome.Reply(reply)
            }
        } catch (_: Exception) {
            Outcome.Rejected
        }
    }
}
