package com.nonroot.firewall

import android.net.VpnService

/**
 * Integration placeholder ONLY.
 * Never establish a TUN interface until a real packet forwarding and blocking
 * implementation is connected: doing so would silently break all device traffic.
 */
class FirewallVpnService : VpnService()
