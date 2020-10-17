package io.github.wulkanowy.signer.hebe.android.app

import android.app.Activity
import android.os.Bundle
import android.util.Log
import io.github.wulkanowy.signer.hebe.android.generateKeyPair
import io.github.wulkanowy.signer.hebe.android.getSignatureValues
import kotlinx.android.synthetic.main.activity_main.*
import java.util.*
import java.util.concurrent.TimeUnit

class SignerActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        generate.setOnClickListener {
            val start = Date()
            val (certificateStr, fingerprintStr, privateKeyStr) = generateKeyPair()
            val end = Date()
            timer.text = getTimeTakenString(start, end)
            certificate.setText(certificateStr)
            fingerprint.setText(fingerprintStr)
            privateKey.setText(privateKeyStr)
        }

        filldata.setOnClickListener {
            certificate.setText("")
            fingerprint.setText("7EBA57E1DDBA1C249D097A9FF1C9CCDD45351A6A".toLowerCase())
            privateKey.setText("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCbF5Tt176EpB4cX5U+PZE0XytjJ9ABDZFaBFDkaexbkuNeuLOaARjQEOlUoBmpZQXxAF8HlYqeTvPiTcnSfQIS6EdqpICuQNdwvy6CHFAe2imkbbB0aHPsGep6zH8ZxHbssazkTCnGy0j2ZtGT2/iy1GEvc/p2bOkCVcR1H1GqFp+/XpfaMwi2SRCwc67K8Fu8TjSDKNvcRT9nuenGoPA1CWoOiOCxhQA6gnB8LULPel6TVDxeBVdYor/z2GxFe/m0pa7XAKzveuUDhH8k8NlNG65MjvZhgy9iFs+eBUq7lCZ0nuIsDzjnUrLSl4ciYKj9d94qrUyF8L8D9Rl+0WlAgMBAAECggEAQ6jg3rNmyxIg0rl0ZG/LjEF26RKR7P5KQLcpouESga3HfzHvsjMCq+OWZvciFhazRd4BQkdwZxGPnfa7ieGzmhtvs1pDu8zU/hE4UClV+EG6NpVpC2Q/sn5KZRijaZoY3eMGQUFatBzCBcLZxYspfbyR3ucLbu9DE+foNB1Fh4u9RCDj3bClTsqPcNBIaLMpYr3f/bM1fFbS9LrJ7AXZQtGg/2MH58WsvV67SiYAQqGCzld/Jp74gmod4Ii0w2XWZ7OeixdF2xr1j7TK0dUUlrrOrb1cgOWSOEXyy3RX/iF7R8uuLXiRfo1URh6VNPoOtrC6fHCrCp1iRBo08qOk4QKBgQDxqLrWA7gKcTr2yQeGfETXOAYi0xqbNj5A9eVC0XngxnFuwWc5zyg3Ps3c0UK2qTSSFv4SoeEHQM+U0+9LjYzIRSUH7zy4zBrBlLtTQCysSuuZ9QfgO55b3/QEYkyx6Hz/z/gg53jKHjsUKIftGMwJ6C1M2svbBNYCsWrUuYcsbQKBgQDN9gkVDABIeWUtKDHyB5HGcVbsg7Ji7GhMjdFA0GB+9kR0doKNctrzxKn65BI2uTWg+mxaw5V+UeJOIaeFsv2uClYJYn1F55VT7NIx3CLFv6zFRSiMSKz2W+NkwGjQqR7D3DeEyalpjeQeMdpHZg27LMbdVkzy/cK8EM9ZQlRLGQKBgQCpB2wn5dIE+85Sb6pj1ugP4Y/pK9+gUQCaT2RcqEingCY3Ye/h75QhkDxOB9CyEwhCZvKv9aqAeES5xMPMBOZD7plIQ34lhB3y6SVdxbV5ja3dshYgMZNCkBMOPfOHPSaxh7X2zfEe7qZEI1Vv8bhF9bA54ZBVUbyfhZlD0cFKwQKBgQC9BnXHb0BDQ8br7twH+ZJ8wkC4yRXLXJVMzUujZJtrarHhAXNIRoVU/MXUkcV1m/3wRGV119M4IAbHFnQdbO0N8kaMTmwS4DxYzh0LzbHMM+JpGtPgDENRx3unWD/aYZzuvQnnQP3O9n7Kh46BwNQRWUMamL3+tY8n83WZwhqC4QKBgBTUzHy0sEEZ3hYgwU2ygbzC0vPladw2KqtKy+0LdHtx5pqE4/pvhVMpRRTNBDiAvb5lZmMB/B3CzoiMQOwczuus8Xsx7bEci28DzQ+g2zt0/bC2Xl+992Ass5PP5NtOrP/9QiTNgoFSCrVnZnNzQqpjCrFsjfOD2fiuFLCD6zi6")
            fullUrl.setText("/powiatwulkanowy/123456/api/mobile/register/hebe")
            content.setText("{}")
        }

        sign.setOnClickListener {
            result.text = try {
                Log.d("signer", "Sign starts...")
                val start = Date()
                val (digest, canonicalUrl, signature) = getSignatureValues(
                    fingerprint.text.toString(),
                    privateKey.text.toString(),
                    content.text.toString(),
                    fullUrl.text.toString(),
                    Date()
                )
                val end = Date()
                Log.d("signer", "Sign ends")
                timer.text = getTimeTakenString(start, end)
                "digest = ${digest}\ncanonicalUrl = ${canonicalUrl}\nsignature = $signature"
            } catch (e: Throwable) {
                Log.d("signer", "Sign errored: ${e.localizedMessage}")
                e.localizedMessage
            }
        }
    }

    private fun getTimeTakenString(start: Date, end: Date): String {
        val diff = end.time - start.time
        return String.format(
            "%d secs (%d ms)",
            TimeUnit.MILLISECONDS.toSeconds(diff),
            diff
        )
    }
}
