defmodule Tango.Live.OAuthHookTest do
  use ExUnit.Case, async: true

  @node System.find_executable("node")
  @moduletag skip: is_nil(@node) && "node is not installed"

  @hook_path Path.expand("../../../assets/tango_oauth_hook.js", __DIR__)
  @demo_paths Path.wildcard(Path.expand("../../../demo/lib/**/*.{ex,exs,heex}", __DIR__)) ++
                Path.wildcard(Path.expand("../../../demo/assets/js/**/*.js", __DIR__))
  @lib_paths Path.wildcard(Path.expand("../../../lib/**/*.ex", __DIR__))

  setup_all do
    harness = Path.expand("../../fixtures/oauth_hook_harness.mjs", __DIR__)
    {output, 0} = System.cmd(@node, [harness], stderr_to_stdout: false)
    %{scenarios: Jason.decode!(output)}
  end

  describe "browser behavior" do
    test "forwards only the opaque handle and intent reference", %{scenarios: scenarios} do
      expected = [
        %{
          "event" => "oauth_complete",
          "payload" => %{
            "completion_handle" => "opaque-handle",
            "intent_reference" => "intent-1"
          }
        }
      ]

      assert scenarios["complete"] == expected
      assert scenarios["complete_with_extra_fields"] == expected
    end

    test "ignores messages from other origins, windows, and intents", %{scenarios: scenarios} do
      assert scenarios["wrong_origin"] == []
      assert scenarios["wrong_source"] == []
      assert scenarios["wrong_intent"] == []
      assert scenarios["no_popup"] == []
      assert scenarios["error_wrong_origin"] == []
    end

    test "rejects legacy token payloads and completions without a handle", %{
      scenarios: scenarios
    } do
      assert scenarios["legacy_connection_payload"] == []
      assert scenarios["missing_handle"] == []
    end

    test "forwards a stable error category", %{scenarios: scenarios} do
      assert scenarios["error"] == [
               %{
                 "event" => "oauth_error",
                 "payload" => %{"error" => "invalid_grant", "intent_reference" => "intent-1"}
               }
             ]
    end
  end

  describe "source contract" do
    test "hook never reads or forwards credentials or connection payloads" do
      source = File.read!(@hook_path)

      assert source =~ "completion_handle"
      assert source =~ "intent_reference"
      assert source =~ "event.origin"
      assert source =~ "event.source"
      refute source =~ ~r/access_token|refresh_token|\.token\b|data\.connection|connection:/
      refute source =~ "console."
    end

    test "package lib, hook, and demo never post an access or refresh token" do
      offenders =
        for path <- [@hook_path | @lib_paths ++ @demo_paths],
            source = File.read!(path),
            source =~ ~r/postMessage\([^)]*(access_token|refresh_token|token:)/s or
              source =~ ~r/token:\s*(exchange|connection)Result/ or
              source =~ ~r/postMessage\([^,]*,\s*['"]\*['"]\)/ do
          Path.relative_to(path, Path.expand("../../..", __DIR__))
        end

      assert offenders == []
    end

    test "demo LiveView consumes the completion handle rather than a token" do
      demo = File.read!(Path.expand("../../../demo/lib/demo_web/live/demo_live.ex", __DIR__))

      assert demo =~ "completion_handle"
      refute demo =~ ~r/%\{token: token/
      refute demo =~ "fetch_github_profile, token"
    end
  end
end
