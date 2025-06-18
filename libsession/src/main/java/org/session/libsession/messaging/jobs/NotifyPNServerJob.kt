package org.session.libsession.messaging.jobs

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.io.Input
import com.esotericsoftware.kryo.io.Output
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import org.session.libsession.messaging.jobs.Job.Companion.MAX_BUFFER_SIZE_BYTES
import org.session.libsession.messaging.messages.Message
import org.session.libsession.messaging.messages.visible.VisibleMessage
import org.session.libsession.messaging.sending_receiving.notifications.Server
import org.session.libsession.messaging.utilities.Data
import org.session.libsession.snode.SnodeMessage
import org.session.libsignal.utilities.JsonUtil
import org.session.libsignal.utilities.Log
import org.session.libsignal.crypto.ecc.Curve
import org.session.libsignal.crypto.kdf.HKDFv3
import org.whispersystems.curve25519.Curve25519
import org.session.libsignal.utilities.retryIfNeeded
import java.io.IOException
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// 暗号化されたリクエストボディの構造 (iOS側と合わせる)
data class EncryptedRequestBody(
    val ephemeralPublicKey: String, // Base64エンコードされた一時公開鍵
    val sealedBox: String // Base64エンコードされたChaChaPolyの結合された出力
)
// --- Custom Promise Definition ---
// retryIfNeeded が期待する Promise の型を解決するために追加されました。
// 実際の Promise の実装は libsignal.utilities 内で異なる場合がありますが、
// ここではシグネチャを満たすことを目的としています。

// 成功値 V と例外 E を持つ Promise のためのジェネリックインターフェース
interface SimplePromise<V, E : Exception> {
    // 成功時と失敗時のコールバックをチェインできるようにする関数
    infix fun success(onSuccess: (V) -> Unit): SimplePromise<V, E>
    infix fun fail(onFail: (E) -> Unit): SimplePromise<V, E>
}

// Result を基にすぐに解決する SimplePromise の具体的な実装
class ImmediatePromise<V, E : Exception>(private val result: Result<V>) : SimplePromise<V, E> {
    override infix fun success(onSuccess: (V) -> Unit): SimplePromise<V, E> {
        result.onSuccess { value ->
            onSuccess(value)
        }
        return this
    }

    override infix fun fail(onFail: (E) -> Unit): SimplePromise<V, E> {
        result.onFailure { throwable ->
            @Suppress("UNCHECKED_CAST") // 投げられた例外が型 E であると仮定
            onFail(throwable as E)
        }
        return this
    }
}

// サスペンドブロックの結果を SimplePromise に変換するヘルパー関数
// これにより、retryIfNeeded が期待する OnionRequestAPI.sendOnionRequest の戻り値を模倣します
suspend fun <V> runAsPromise(block: suspend () -> V): SimplePromise<V, Exception> {
    return try {
        val value = block()
        ImmediatePromise(Result.success(value))
    } catch (e: Exception) {
        ImmediatePromise(Result.failure(e))
    }
}
// --- End of Custom Promise Definition ---


class NotifyPNServerJob(val message: VisibleMessage) : Job {
    override var delegate: JobDelegate? = null
    override var id: String? = null
    override var failureCount: Int = 0

    override val maxFailureCount: Int = 20
    companion object {
        val KEY: String = "NotifyPNServerJob"

        // データベース保存に使用されるキー
        private val MESSAGE_KEY = "message"

        // OkHttpClient インスタンスをシングルトンとして保持する (または DI で提供する)
        val okHttpClient = OkHttpClient()
        val hKDFv3 = HKDFv3.createFor(3)
        fun String.decodeHex(): ByteArray {
            check(length % 2 == 0) { "Must have an even length" }

            return chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        }
        /**
         * CryptoKitを使ってリクエストボディを暗号化する (iOSコードをKotlinに移植)
         * ChaChaPolyとCurve25519キーアグリーメントを使用
         */
        @OptIn(ExperimentalStdlibApi::class)
        fun encryptBody(plaintext: ByteArray): String {

            val server = Server.LEGACY

            val serverPublicKeyBytes = server.publicKey.decodeHex()
            //Log.d("NotifyPNServerJob", "Server public key: ${server.publicKey}")
            //val serverKey = Curve.decodePoint(serverPublicKeyBytes, 0)
            // クライアントの一時的なキーペアを生成
            val clientKeyPair = Curve.generateKeyPair()
            val clientPrivateKey = clientKeyPair.privateKey
            var clientPrivateKeyDecoded = clientPrivateKey.serialize()
            if (clientPrivateKeyDecoded.size == 33) {
                clientPrivateKeyDecoded = clientPrivateKeyDecoded.sliceArray(1 until clientPrivateKeyDecoded.size)
            }

            val clientPublicKey = clientKeyPair.publicKey
            var clientPublicKeyDecoded = clientPublicKey.serialize()
            if (clientPublicKeyDecoded.size == 33) {
                clientPublicKeyDecoded = clientPublicKeyDecoded.sliceArray(1 until clientPublicKeyDecoded.size)
            }

            // 共通鍵を生成 (Curve25519 キーアグリーメント)
            // libsignalのCurve25519クラスのsharedSecretメソッドを使用
            val sharedSecret = Curve25519.getInstance(Curve25519.BEST).calculateAgreement(serverPublicKeyBytes, clientPrivateKeyDecoded)
            //Log.d("CryptoDebug", "Shared secret (hex): ${sharedSecret.toHexString()}")


            // 共通鍵から対称キーを導出 (HKDF)
            // libsignalのHKDF実装またはCommons Cryptoなどのライブラリを使用できます
            // ここでは、単純なSecureRandomからのキー生成を模倣していますが、
            // 実際のHKDF実装に置き換える必要があります。
            // FIXME: 適切なHKDF実装を使用してください。例えば libsignal-protocol-java に含まれる HKDF.deriveSecrets()
            val clientInfo = ByteArray(0)
            val clientSalt = ByteArray(32)
            //Log.d("CryptoDebug", "Client info (hex): ${clientInfo.toHexString()}")
            val symmetricKeyBytes = hKDFv3.deriveSecrets(sharedSecret, clientInfo, 32) // 32バイト (256ビット)
            val symmetricKey = SecretKeySpec(symmetricKeyBytes, "ChaCha20-Poly1305")
            //Log.d("CryptoDebug", "Shared secret (hex): ${symmetricKey}")

            // ChaChaPolyで平文を暗号化
            val nonce = ByteArray(12) // ChaChaPolyVFSの場合、Nonceは12バイト
            SecureRandom().nextBytes(nonce)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305") // または "ChaCha20-Poly1305/None/NoPadding"
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, IvParameterSpec(nonce))

            val ciphertextWithTag = cipher.doFinal(plaintext) //sealedbox

            // 暗号文とタグを結合 (iOSのsealedBox.combinedに相当)
            // ChaChaPolyでは通常、タグは暗号文の末尾に追加される
            val sealedBoxCombined = nonce + ciphertextWithTag
            //Log.d("NotifyPNServerJob", "plainText: ${plaintext.toString(Charsets.UTF_8)} ")
            //Log.d("NotifyPNServerJob", "sealedBox: ${Base64.getEncoder().encodeToString(sealedBoxCombined)} ")
            // 送信用のリクエストボディを作成
            val encryptedRequest = EncryptedRequestBody(
                ephemeralPublicKey = Base64.getEncoder().encodeToString(clientPublicKeyDecoded),
                sealedBox = Base64.getEncoder().encodeToString(sealedBoxCombined)
            )

            return JsonUtil.toJson(encryptedRequest)
        }
    }
    override suspend fun execute(dispatcherName: String) {
        val server = Server.LEGACY
        val parameters = mapOf( "data" to (message.text?.take(30) ?: "You got a new message."), "send_to" to message.recipient )
        val url = "${server.url}/notify"
        val body = RequestBody.create("application/json".toMediaType(), encryptBody(JsonUtil.toJson(parameters).toByteArray(charset = Charsets.UTF_8)))
        val request = Request.Builder().url(url).post(body).build()

        // OkHttpClient の呼び出しと結果の処理を Promise でラップします
        runAsPromise { // ここで runAsPromise を呼び出し、Promise<Response, Exception> を返します
            val response: Response = okHttpClient.newCall(request).execute()

            if (response.isSuccessful) {
                Log.d("NotifyPNServerJob", "Successfully notified PN server. Response Code: ${response.code}.")
                response // 成功時にはレスポンスを返します
            } else {
                val errorMessage = "Failed to notify PN server. Code: ${response.code}, Message: ${response.message}, Body: ${response.body?.string()}."
                Log.d("NotifyPNServerJob", errorMessage)
                // 失敗時には IOException をスローし、これが runAsPromise によって捕捉され PromiseFailure になります
                throw IOException(errorMessage)
            }
        } success {
            // retryIfNeeded の最終的な成功ハンドラ
            handleSuccess(dispatcherName)
        } fail { exception:Exception ->
            // retryIfNeeded の最終的な失敗ハンドラ
            handleFailure(dispatcherName, exception)
        }
    }

    private fun handleSuccess(dispatcherName: String) {
        delegate?.handleJobSucceeded(this, dispatcherName)
    }

    private fun handleFailure(dispatcherName: String, error: Exception) {
        delegate?.handleJobFailed(this, dispatcherName, error)
    }

    override fun serialize(): Data {
        val kryo = Kryo()
        kryo.isRegistrationRequired = false
        val serializedMessage = ByteArray(4096) // Kryo のバッファサイズは必要に応じて調整してください
        val output = Output(serializedMessage, MAX_BUFFER_SIZE_BYTES)
        kryo.writeObject(output, message)
        output.close()
        return Data.Builder()
            .putByteArray(MESSAGE_KEY, serializedMessage)
            .build();
    }

    override fun getFactoryKey(): String {
        return KEY
    }

    class Factory : Job.Factory<NotifyPNServerJob> {

        override fun create(data: Data): NotifyPNServerJob {
            val serializedMessage = data.getByteArray(MESSAGE_KEY)
            val kryo = Kryo()
            kryo.isRegistrationRequired = false
            val input = Input(serializedMessage)
            val message = kryo.readObject(input, VisibleMessage::class.java)
            input.close()
            return NotifyPNServerJob(message)
        }
    }
}
