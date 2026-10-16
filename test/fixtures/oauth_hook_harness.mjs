// Drives assets/tango_oauth_hook.js against a minimal fake browser and prints
// the events the hook forwards to the LiveComponent as JSON.
import TangoOAuth from "../../assets/tango_oauth_hook.js"

const callbackOrigin = "https://api.example.test"
const listeners = {}
const popup = { closed: false, focus() {}, close() { this.closed = true } }
const otherWindow = { closed: false, focus() {}, close() {} }

globalThis.window = {
  addEventListener: (type, fn) => { listeners[type] = fn },
  removeEventListener: () => {},
  open: () => popup,
  screenX: 0,
  screenY: 0,
  outerWidth: 1200,
  outerHeight: 800,
}

const pushed = []
const handlers = {}
const hook = Object.create(TangoOAuth)
hook.el = { dataset: { componentId: "oauth" } }
hook.pushEventTo = (selector, event, payload) => pushed.push({ selector, event, payload })
hook.handleEvent = (name, fn) => { handlers[name] = fn }
hook.mounted()

const open = () => {
  popup.closed = false
  handlers.open_popup({
    url: "https://provider.example.test/authorize",
    intent_reference: "intent-1",
    callback_origin: callbackOrigin,
  })
}

const scenarios = {}
const run = (name, event) => {
  open()
  pushed.length = 0
  listeners.message(event)
  scenarios[name] = pushed.map((entry) => ({ event: entry.event, payload: entry.payload }))
  hook.cleanup()
}

const good = {
  type: "oauth_complete",
  completion_handle: "opaque-handle",
  intent_reference: "intent-1",
}

run("complete", { source: popup, origin: callbackOrigin, data: good })
run("complete_with_extra_fields", {
  source: popup,
  origin: callbackOrigin,
  data: { ...good, token: "leaked-token", connection: { token: "leaked-token" } },
})
run("wrong_origin", { source: popup, origin: "https://evil.example.test", data: good })
run("wrong_source", { source: otherWindow, origin: callbackOrigin, data: good })
run("wrong_intent", {
  source: popup,
  origin: callbackOrigin,
  data: { ...good, intent_reference: "intent-2" },
})
run("legacy_connection_payload", {
  source: popup,
  origin: callbackOrigin,
  data: { type: "oauth_complete", connection: { token: "legacy-token" } },
})
run("missing_handle", {
  source: popup,
  origin: callbackOrigin,
  data: { type: "oauth_complete", intent_reference: "intent-1" },
})
run("error", {
  source: popup,
  origin: callbackOrigin,
  data: { type: "oauth_error", error: "invalid_grant", intent_reference: "intent-1" },
})
run("error_wrong_origin", {
  source: popup,
  origin: "https://evil.example.test",
  data: { type: "oauth_error", error: "invalid_grant", intent_reference: "intent-1" },
})

// Messages that arrive with no popup open are ignored.
pushed.length = 0
listeners.message({ source: popup, origin: callbackOrigin, data: good })
scenarios.no_popup = pushed.map((entry) => ({ event: entry.event, payload: entry.payload }))

hook.destroyed()
console.log(JSON.stringify(scenarios))
