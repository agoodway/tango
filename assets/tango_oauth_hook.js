/**
 * TangoOAuth LiveView Hook
 *
 * Manages the OAuth popup window lifecycle:
 * - Opens a centered popup when instructed by the server
 * - Listens for postMessage from the OAuth callback page
 * - Accepts only messages from the popup window, from the callback page's
 *   origin, for the intent the server started
 * - Forwards the opaque completion handle (never a token) back to the
 *   LiveComponent, which hands it to the authenticated server-side completion
 * - Monitors popup close state
 *
 * Register with LiveSocket:
 *   import TangoOAuth from "../../deps/tango/assets/tango_oauth_hook.js"
 *   let liveSocket = new LiveSocket("/live", Socket, { hooks: { TangoOAuth } })
 */
const TangoOAuth = {
  mounted() {
    this.popup = null
    this.pending = null
    this.pollInterval = null
    this.componentId = this.el.dataset.componentId

    this.messageHandler = (event) => {
      if (!this.popup || !this.pending) return
      if (event.source !== this.popup) return
      if (event.origin !== this.pending.callbackOrigin) return

      const data = event.data
      if (!data || typeof data !== "object") return
      if (data.intent_reference !== this.pending.intentReference) return

      const target = `#${this.componentId}`
      const intentReference = this.pending.intentReference

      if (data.type === "oauth_complete") {
        if (typeof data.completion_handle !== "string" || data.completion_handle === "") return

        this.pushEventTo(target, "oauth_complete", {
          completion_handle: data.completion_handle,
          intent_reference: intentReference
        })
        this.cleanup()
      } else if (data.type === "oauth_error") {
        this.pushEventTo(target, "oauth_error", {
          error: typeof data.error === "string" ? data.error : "oauth_failed",
          intent_reference: intentReference
        })
        this.cleanup()
      }
    }

    window.addEventListener("message", this.messageHandler)

    this.handleEvent("open_popup", ({ url, intent_reference, callback_origin }) => {
      const width = 600
      const height = 700
      const left = window.screenX + (window.outerWidth - width) / 2
      const top = window.screenY + (window.outerHeight - height) / 2

      this.pending = {
        intentReference: intent_reference,
        callbackOrigin: callback_origin
      }

      this.popup = window.open(
        url,
        "tango_oauth_popup",
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`
      )

      if (this.popup) {
        this.popup.focus()
        this.startPolling()
      } else {
        this.pending = null
      }
    })
  },

  startPolling() {
    this.pollInterval = setInterval(() => {
      if (this.popup && this.popup.closed) {
        this.pushEventTo(`#${this.componentId}`, "popup_closed", {})
        this.cleanup()
      }
    }, 1000)
  },

  cleanup() {
    if (this.pollInterval) {
      clearInterval(this.pollInterval)
      this.pollInterval = null
    }
    if (this.popup && !this.popup.closed) {
      this.popup.close()
    }
    this.popup = null
    this.pending = null
  },

  destroyed() {
    window.removeEventListener("message", this.messageHandler)
    this.cleanup()
  }
}

export default TangoOAuth
