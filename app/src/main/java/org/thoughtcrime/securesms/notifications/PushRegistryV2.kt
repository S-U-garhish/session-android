package org.thoughtcrime.securesms.notifications

import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import org.session.libsession.messaging.jobs.NotifyPNServerJob
import org.session.libsession.messaging.jobs.NotifyPNServerJob.Companion.encryptBody
import org.session.libsession.messaging.notifications.TokenFetcher
import org.session.libsession.messaging.sending_receiving.notifications.Response
import org.session.libsession.messaging.sending_receiving.notifications.Server
import org.session.libsession.messaging.sending_receiving.notifications.SubscriptionRequest
import org.session.libsession.messaging.sending_receiving.notifications.SubscriptionResponse
import org.session.libsession.messaging.sending_receiving.notifications.UnsubscribeResponse
import org.session.libsession.messaging.sending_receiving.notifications.UnsubscriptionRequest
import org.session.libsession.snode.OwnedSwarmAuth
import org.session.libsession.snode.SnodeClock
import org.session.libsession.snode.SwarmAuth
import org.session.libsession.utilities.Device
import org.session.libsignal.utilities.JsonUtil
import org.session.libsignal.utilities.Log
import org.session.libsignal.utilities.retryWithUniformInterval
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton
import org.thoughtcrime.securesms.dependencies.ConfigFactory

private const val maxRetryCount = 1

@Singleton
class PushRegistryV2 @Inject constructor(

    private val pushReceiver: PushReceiver,
    private val device: Device,
    private val clock: SnodeClock,
    ) {
    suspend fun register(
        addedAccountIds: Set<PushRegistrationHandler.SubscriptionKey>,
        userAuth: OwnedSwarmAuth,
    ) {
        val tokenFetcher: TokenFetcher = FirebaseTokenFetcher()
        val pnKey = tokenFetcher.fetch()
        var publicClosedGroupKeys = getAccountIdsAsHexStringList(addedAccountIds)
        val myPubKey = userAuth.accountId.hexString

        //publicClosedGroupKeys.map { key ->
        //    Log.d("PushRegistry", key)
        //}
        //currentKeys.map { key ->
        //    Log.d("PushRegistry", key.value.accountId.hexString)
        //}

        publicClosedGroupKeys = publicClosedGroupKeys.filterNot { key -> myPubKey == key }

        val timestamp = clock.currentTimeMills() / 1000 // get timestamp in ms -> s
        //val publicKey = swarmAuth.accountId.hexString
        //val sortedNamespace = namespaces.sorted()
        //val signed = swarmAuth.sign(
        //    "MONITOR${publicKey}${timestamp}1${sortedNamespace.joinToString(separator = ",")}".encodeToByteArray()
        //)

        val requestParameters = SubscriptionRequest(
            pubKey = myPubKey,
            token = pnKey,
            closedGroupPublicKey = publicClosedGroupKeys,
            data = true, // only permit data subscription for now (?)
            service = device.service,//"firebase"
            sig_ts = timestamp,
            //service_info = mapOf("token" to token),
        ).let(Json::encodeToJsonElement).jsonObject// + signed

        val response = retryResponseBody<SubscriptionResponse>(
            "subscribe_closed_group",
            Json.encodeToString(requestParameters)
        )

        check(response.isSuccess()) {
            "Error subscribing to push notifications: ${response.message}"
        }
    }

    suspend fun unregister(
        removedAccountIds: Set<PushRegistrationHandler.SubscriptionKey>,
        userAuth: OwnedSwarmAuth,
    ) {

        val publicClosedGroupKeys = getAccountIdsAsHexStringList(removedAccountIds)
        val myPubKey = userAuth.accountId.hexString
        
        val timestamp = clock.currentTimeMills() / 1000 // get timestamp in ms -> s
        // if we want to support passing namespace list, here is the place to do it
        //val signature = swarmAuth.signForPushRegistry(
        //    "UNSUBSCRIBE${publicKey}${timestamp}".encodeToByteArray()
        //)

        val requestParameters = UnsubscriptionRequest(
            pubKey = myPubKey,
            closedGroupPublicKey = publicClosedGroupKeys,
            service = device.service,
            sig_ts = timestamp,
            //service_info = mapOf("token" to token),
        ).let(Json::encodeToJsonElement).jsonObject

        val response: UnsubscribeResponse = retryResponseBody<UnsubscribeResponse>("unsubscribe_closed_group", Json.encodeToString(requestParameters))

        check(response.isSuccess()) {
            "Error unsubscribing to push notifications: ${response.message}"
        }
    }
    fun getAccountIdsAsHexStringList(subscriptionKeys: Set<PushRegistrationHandler.SubscriptionKey>): List<String> {
        return subscriptionKeys.map{ key -> key.accountId.hexString }
    }
    private operator fun JsonObject.plus(additional: Map<String, String>): JsonObject {
        return JsonObject(buildMap {
            putAll(this@plus)
            for ((key, value) in additional) {
                put(key, JsonPrimitive(value))
            }
        })
    }

    private suspend inline fun <reified T: Response> retryResponseBody(path: String, requestParameters: String): T =
        retryWithUniformInterval(maxRetryCount = maxRetryCount) { getResponseBody(path, requestParameters) }

    @OptIn(ExperimentalSerializationApi::class)
    private suspend inline fun <reified T: Response> getResponseBody(path: String, requestParameters: String): T {
        val server = Server.LATEST
        val url = "${server.url}/$path"
        val body = RequestBody.create("application/json".toMediaType(), encryptBody(requestParameters.toByteArray(charset = Charsets.UTF_8)))
        val request = Request.Builder().url(url).post(body).build()
        // OkHttpClient の呼び出しと結果の処理を Promise でラップします
        val response: okhttp3.Response = NotifyPNServerJob.okHttpClient.newCall(request).execute()

        if (response.isSuccessful) {
            Log.d("NotifyPNServerJob", "Successfully notified PN server. Response Code: ${response.code}.")
            requireNotNull(response.body){"Response doesn't have a body"}
            return Json.decodeFromString<T>(response.body!!.string())
        } else {
            val errorMessage = "Failed to notify PN server. Code: ${response.code}, Message: ${response.message}, Body: ${response.body?.string()}."
            Log.d("NotifyPNServerJob", errorMessage)
            // 失敗時には IOException をスローし、これが runAsPromise によって捕捉され PromiseFailure になります
            throw IOException(errorMessage)
        }

    }
}