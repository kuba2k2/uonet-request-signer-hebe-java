package io.github.wulkanowy.signer.hebe.android

import com.migcomponents.migbase64.Base64
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.net.URLEncoder
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.*
import java.security.MessageDigest.getInstance as createSign

private fun getDigest(body: String?): String {
    if (body == null) return ""
    return Base64.encodeToString(createSign("SHA-256").digest(body.toByteArray()), false)
}

private fun getSignatureValue(values: String, privateKey: String): String {
    val bl = Base64.decode(privateKey)
    val spec = PKCS8EncodedKeySpec(bl)
    val kf = KeyFactory.getInstance("RSA")

    val privateSignature = Signature.getInstance("SHA256withRSA")
    privateSignature.initSign(kf.generatePrivate(spec))
    privateSignature.update(values.toByteArray())

    return Base64.encodeToString(privateSignature.sign(), false)
}

private fun getEncodedPath(path: String): String {
    val url = ("(api/mobile/.+)".toRegex().find(path))
        ?: throw IllegalArgumentException("The URL does not seem correct (does not match `(api/mobile/.+)` regex)")

    return URLEncoder.encode(url.groupValues[0], "UTF-8").orEmpty().toLowerCase()
}

private fun getHeadersList(body: String?, digest: String, canonicalUrl: String, timestamp: Date): Pair<String, String> {
    val signData = mutableMapOf<String, String>()
    signData["vCanonicalUrl"] = canonicalUrl
    if (body != null) signData["Digest"] = digest
    signData["vDate"] = SimpleDateFormat("EEE, d MMM yyyy hh:mm:ss", Locale.ENGLISH).apply {
        timeZone = TimeZone.getTimeZone("GMT")
    }.format(timestamp) + " GMT"

    return Pair(
        first = signData.keys.joinToString(" "),
        second = signData.values.joinToString("")
    )
}

fun getSignatureValues(
    fingerprint: String,
    privateKey: String,
    body: String?,
    requestPath: String,
    timestamp: Date
): Triple<String, String, String> {
    val canonicalUrl = getEncodedPath(requestPath)
    val digest = getDigest(body)
    val (headers, values) = getHeadersList(body, digest, canonicalUrl, timestamp)
    val signatureValue = getSignatureValue(values, privateKey)

    return Triple(
        "SHA-256=${digest}",
        canonicalUrl,
        """keyId="$fingerprint",headers="$headers",algorithm="sha256withrsa",signature=Base64(SHA256withRSA($signatureValue))"""
    )
}

fun generateKeyPair(): Triple<String, String, String> {
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    val keyPair = generator.generateKeyPair()
    val publicKey = keyPair.public
    val privateKey = keyPair.private

    val bcProvider = BouncyCastleProvider()
    Security.addProvider(bcProvider)

    val now = System.currentTimeMillis()
    val notBefore = Date(now)

    val name = X500Name("CN=APP_CERTIFICATE CA Certificate")

    val notAfter = Calendar.getInstance()
    notAfter.time = notBefore
    notAfter.add(Calendar.YEAR, 20)

    val contentSigner = JcaContentSignerBuilder("SHA256withRSA")
        .build(privateKey)

    val certBuilder = JcaX509v3CertificateBuilder(
        name,
        BigInteger.ONE,
        notBefore,
        notAfter.time,
        name,
        publicKey
    )

    val cert = JcaX509CertificateConverter()
        .setProvider(bcProvider)
        .getCertificate(certBuilder.build(contentSigner))

    val certificatePem = Base64.encodeToString(cert.encoded, false)
    val fingerprint = createSign("SHA-1")
        .digest(cert.encoded)
        .joinToString("") { "%02x".format(it) }
    val privateKeyPem = Base64.encodeToString(privateKey.encoded, false)
    return Triple(certificatePem, fingerprint, privateKeyPem)
}
