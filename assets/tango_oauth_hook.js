/**
 * TangoOAuth LiveView Hook
 *
 * Manages the OAuth popup window lifecycle:
 * - Opens a centered popup when instructed by the server
 * - Listens for postMessage from the OAuth callback page
 * - Forwards results back to the LiveComponent
 * - Monitors popup close state
 *
 * Register with LiveSocket:
 *   import TangoOAuth from "../../deps/tango/assets/tango_oauth_hook.js"
 *   let liveSocket = new LiveSocket("/live", Socket, { hooks: { TangoOAuth } })
 */
const TangoOAuth = {
  mounted() {
    this.popup = null
    this.pollInterval = null
    this.componentId = this.el.dataset.componentId

    this.messageHandler = (event) => {
      if (!this.popup) return

      const data = event.data
      if (!data || !data.type) return

      if (data.type === "oauth_complete") {
        this.pushEventTo(`#${this.componentId}`, "oauth_complete", {
          connection: data.connection
        })
        this.cleanup()
      } else if (data.type === "oauth_error") {
        this.pushEventTo(`#${this.componentId}`, "oauth_error", {
          error: data.error
        })
        this.cleanup()
      }
    }

    window.addEventListener("message", this.messageHandler)

    this.handleEvent("open_popup", ({ url }) => {
      const width = 600
      const height = 700
      const left = window.screenX + (window.outerWidth - width) / 2
      const top = window.screenY + (window.outerHeight - height) / 2

      this.popup = window.open(
        url,
        "tango_oauth_popup",
        `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`
      )

      if (this.popup) {
        this.popup.focus()
        this.startPolling()
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
  },

  destroyed() {
    window.removeEventListener("message", this.messageHandler)
    this.cleanup()
  }
}

export default TangoOAuth
