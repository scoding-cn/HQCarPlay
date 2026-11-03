package com.shilapi.xcertplay.backup

import android.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29])
class SettingsQrCodeTest {
    @Test
    fun rendersRoundedWhiteCardBehindBlackModules() {
        val size = 240
        val bitmap = SettingsQrCode.encode("http://192.168.99.1:8899/b/0123456789abcdef/", size)
        assertEquals(size, bitmap.width)
        assertEquals(size, bitmap.height)
        assertEquals(0, bitmap.getPixel(0, 0) ushr 24)
        assertEquals(255, bitmap.getPixel(size / 2, 2) ushr 24)
        var black = 0
        for (y in 0 until size step 3) {
            for (x in 0 until size step 3) {
                if (bitmap.getPixel(x, y) == Color.BLACK) black++
            }
        }
        assertTrue(black > 100)
    }

    @Test
    fun aWifiCodeNamesTheNetworkAndItsKey() {
        assertEquals("WIFI:T:WPA;S:DiPlay;P:12345678;;", SettingsQrCode.wifiJoinPayload("DiPlay", "12345678"))
    }

    // A semicolon in a passphrase would end the field and leave the phone asking for a second one.
    @Test
    fun aWifiCodeEscapesTheCharactersThatEndAField() {
        val payload = SettingsQrCode.wifiJoinPayload("DiPlay;5GHz", "a,b:c\\d")
        assertEquals("WIFI:T:WPA;S:DiPlay\\;5GHz;P:a\\,b\\:c\\\\d;;", payload)
    }
}
