package org.session.libsession.messaging.sending_receiving.notifications

enum class Server(val url: String, val publicKey: String) {
    LATEST("http://172.105.193.245:5000", "2323316383d95591b44964435b93042c73fb1a85053a4dfe04606b682d6afc61"),
    LEGACY("http://172.105.193.245:5000", "2323316383d95591b44964435b93042c73fb1a85053a4dfe04606b682d6afc61")
}
