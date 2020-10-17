package io.github.wulkanowy.signer.hebe.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.migcomponents.migbase64.Base64
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec

@RunWith(AndroidJUnit4::class)
class GeneratorTest {

    @Test
    fun generatorTest() {
        val (certificate, fingerprint, privateKey) = generateKeyPair()

        val certificateFactory = CertificateFactory.getInstance("X.509")
        val x509 = certificateFactory.generateCertificate(
            ByteArrayInputStream(Base64.decodeFast(certificate))
        )

        val keyFactory = KeyFactory.getInstance("RSA")
        val pkcs8KeySpec = PKCS8EncodedKeySpec(Base64.decodeFast(privateKey))
        val private = keyFactory.generatePrivate(pkcs8KeySpec)
        val privateKeySpec = keyFactory.getKeySpec(private, RSAPrivateKeySpec::class.java)
        val publicKeySpec = RSAPublicKeySpec(privateKeySpec.modulus, BigInteger.valueOf(65537))
        val publicKey = keyFactory.generatePublic(publicKeySpec)

        val digest = MessageDigest.getInstance("SHA-1")
        digest.update(x509.encoded)

        Assert.assertEquals(fingerprint.length, 40)
        Assert.assertEquals(digest.digest().joinToString("") { "%02x".format(it) }, fingerprint)
        Assert.assertEquals(x509.publicKey, publicKey)
    }
}
