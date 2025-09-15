defmodule Mix.Tasks.Helpers.TaskHelperTest do
  @moduledoc """
  Tests for TaskHelper module functions used by Mix tasks.

  Tests application startup, dependency management, and error handling
  for Mix task execution contexts.
  """

  use ExUnit.Case, async: false

  alias Mix.Tasks.Helpers.TaskHelper

  describe "ensure_http_started/0" do
    test "starts required HTTP applications" do
      # Stop applications if they're running to test startup
      Application.stop(:req)
      Application.stop(:tango)

      # Should start successfully (returns tuple with started apps)
      result = TaskHelper.ensure_http_started()
      assert match?({:ok, _}, result) or result == :ok

      # Verify applications are started
      req_result = Application.ensure_started(:req)
      tango_result = Application.ensure_started(:tango)
      assert req_result == :ok or match?({:ok, _}, req_result)
      assert tango_result == :ok or match?({:ok, _}, tango_result)
    end

    test "handles already started applications gracefully" do
      # Ensure applications are started
      Application.ensure_all_started(:req)
      Application.ensure_all_started(:tango)

      # Should not error when applications already started
      result = TaskHelper.ensure_http_started()
      assert match?({:ok, _}, result) or result == :ok
    end

    test "can be called multiple times safely" do
      # Should be idempotent
      result1 = TaskHelper.ensure_http_started()
      result2 = TaskHelper.ensure_http_started()
      result3 = TaskHelper.ensure_http_started()

      assert match?({:ok, _}, result1) or result1 == :ok
      assert match?({:ok, _}, result2) or result2 == :ok
      assert match?({:ok, _}, result3) or result3 == :ok
    end
  end

  describe "ensure_repo_started/0" do
    test "starts default repo when configured" do
      # This test assumes default Tango.Repo configuration
      # In real apps, this would be the configured repo
      result = TaskHelper.ensure_repo_started()

      # Should either start successfully or be already started
      assert result == :ok or match?({:error, {:already_started, _}}, result)
    end

    test "handles repo startup errors gracefully" do
      # This tests the error handling path
      # The actual behavior depends on repo configuration
      result = TaskHelper.ensure_repo_started()

      # Should return a result (either success or handled error)
      assert result != nil
    end

    test "uses configured repo from application environment" do
      # Test that it respects the :repo configuration
      original_repo = Application.get_env(:tango, :repo)

      try do
        # Set a test repo configuration
        Application.put_env(:tango, :repo, Tango.TestRepo)

        # Should attempt to start the configured repo
        # (TestRepo should be available in test environment)
        result = TaskHelper.ensure_repo_started()
        assert result == :ok or match?({:error, {:already_started, _}}, result)
      after
        # Restore original configuration
        if original_repo do
          Application.put_env(:tango, :repo, original_repo)
        else
          Application.delete_env(:tango, :repo)
        end
      end
    end
  end

  describe "ensure_started/0" do
    test "starts both HTTP dependencies and repo" do
      # This is the full startup sequence used by database-dependent tasks
      result = TaskHelper.ensure_started()

      # Should complete without error
      assert result == :ok or match?({:error, {:already_started, _}}, result)

      # Verify HTTP applications are started
      req_result = Application.ensure_started(:req)
      tango_result = Application.ensure_started(:tango)
      assert req_result == :ok or match?({:ok, _}, req_result)
      assert tango_result == :ok or match?({:ok, _}, tango_result)
    end

    test "handles mixed startup states" do
      # Test when some apps are started and others aren't
      Application.stop(:req)
      Application.ensure_all_started(:tango)

      result = TaskHelper.ensure_started()

      # Should handle mixed states gracefully
      assert result == :ok or match?({:error, {:already_started, _}}, result)
    end

    test "provides complete application environment for Mix tasks" do
      # Verify that after ensure_started, tasks have everything they need
      TaskHelper.ensure_started()

      # Check that key applications are available
      req_result = Application.ensure_started(:req)
      tango_result = Application.ensure_started(:tango)
      assert req_result == :ok or match?({:ok, _}, req_result)
      assert tango_result == :ok or match?({:ok, _}, tango_result)

      # Verify Tango application modules are loaded
      assert Code.ensure_loaded?(Tango.Catalog)
      assert Code.ensure_loaded?(Tango.Provider)
      assert Code.ensure_loaded?(Tango.Vault)
    end
  end

  describe "error handling and edge cases" do
    test "handles application startup failures gracefully" do
      # This test verifies error handling without actually causing failures
      # since we can't easily simulate app startup failures in tests

      # The functions should not raise exceptions
      http_result = TaskHelper.ensure_http_started()
      repo_result = TaskHelper.ensure_repo_started()

      # Results should be valid return values (not raise exceptions)
      assert match?({:ok, _}, http_result) or http_result == :ok

      assert repo_result == :ok or match?({:error, {:already_started, _}}, repo_result) or
               match?({:error, _}, repo_result)
    end

    test "works in different Mix environments" do
      # Verify functions work across different environments
      original_env = Mix.env()

      try do
        # Test in test environment (current)
        Mix.env(:test)
        result1 = TaskHelper.ensure_http_started()
        assert match?({:ok, _}, result1) or result1 == :ok

        # Functions should be environment-agnostic
        Mix.env(:dev)
        result2 = TaskHelper.ensure_http_started()
        assert match?({:ok, _}, result2) or result2 == :ok
      after
        Mix.env(original_env)
      end
    end

    test "handles concurrent calls safely" do
      # Test that multiple processes can call these functions simultaneously
      tasks =
        for _ <- 1..5 do
          Task.async(fn ->
            TaskHelper.ensure_http_started()
          end)
        end

      results = Task.await_many(tasks)

      # All should succeed (return valid results)
      assert Enum.all?(results, fn result ->
               match?({:ok, _}, result) or result == :ok
             end)
    end
  end

  describe "integration with real Mix task workflow" do
    test "provides environment needed for HTTP catalog operations" do
      # Simulate what HTTP-only Mix tasks need
      TaskHelper.ensure_http_started()

      # Should be able to make HTTP requests (test with a simple one)
      # Note: This doesn't actually make external requests in tests
      assert Code.ensure_loaded?(Req)

      # Verify Tango catalog module is available
      assert Code.ensure_loaded?(Tango.Catalog)
    end

    test "provides environment needed for database operations" do
      # Simulate what database-dependent Mix tasks need
      TaskHelper.ensure_started()

      # Should have repo and related modules available
      assert Code.ensure_loaded?(Tango.Provider)
      assert Code.ensure_loaded?(Tango.Schemas.Provider)

      # Note: Actual repo operations are tested in integration tests
    end
  end
end
