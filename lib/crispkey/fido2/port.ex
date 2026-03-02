defmodule Crispkey.FIDO2.Port do
  @moduledoc """
  Port interface to Python fido2-shim for YubiKey communication.

  Uses python-fido2 library instead of fido2-tools CLI commands.
  """

  alias Crispkey.FIDO2.Types

  @shim_path Path.join(:code.priv_dir(:crispkey), "../../scripts/fido2-shim.py")

  defp shim_path do
    case File.exists?(@shim_path) do
      true ->
        @shim_path

      false ->
        script_path = Path.join(Application.app_dir(:crispkey), "../../scripts/fido2-shim.py")

        case File.exists?(script_path) do
          true -> script_path
          false -> Path.join(File.cwd!(), "scripts/fido2-shim.py")
        end
    end
  end

  defp shim_executable do
    System.find_executable("python3") || System.find_executable("python")
  end

  @spec available?() :: boolean()
  def available? do
    shim_executable() != nil && File.exists?(shim_path())
  end

  defp start_port do
    python = shim_executable()
    path = shim_path()

    Port.open({:spawn_executable, python}, [
      {:args, [path]},
      :binary,
      :exit_status,
      :use_stdio,
      :stderr_to_stdout
    ])
  end

  @spec send_command(map()) :: {:ok, map()} | {:error, term()}
  def send_command(cmd) when is_map(cmd) do
    port = start_port()

    try do
      json_cmd = Jason.encode!(cmd)
      send(port, {self(), {:command, json_cmd <> "\n"}})

      result = receive_response(port, "")

      case result do
        {:ok, %{"error" => error}} ->
          {:error, error}

        {:ok, response} ->
          {:ok, response}

        {:error, reason} ->
          {:error, reason}
      end
    after
      Port.close(port)
    end
  end

  defp receive_response(port, acc, timeout \\ 30_000) do
    receive do
      {^port, {:data, data}} ->
        combined = acc <> data

        case Jason.decode(combined) do
          {:ok, result} ->
            {:ok, result}

          {:error, %Jason.DecodeError{position: _, data: ^combined}} ->
            receive_response(port, combined, timeout)
        end

      {^port, {:exit_status, status}} when status > 0 ->
        {:error, {:exit_status, status, acc}}

      {^port, :closed} ->
        case Jason.decode(acc) do
          {:ok, result} -> {:ok, result}
          {:error, _} -> {:error, :port_closed}
        end
    after
      timeout ->
        {:error, :timeout}
    end
  end

  @spec list_devices() :: {:ok, [map()]} | {:error, term()}
  def list_devices do
    case send_command(%{action: "list_devices"}) do
      {:ok, %{"devices" => devices}} ->
        {:ok, devices}

      {:ok, %{"error" => error}} ->
        {:error, error}

      error ->
        error
    end
  end

  @spec enroll(String.t(), binary(), binary()) ::
          {:ok, map()} | {:error, term()}
  def enroll(pin, user_id, challenge) do
    cmd = %{
      action: "enroll",
      pin: pin,
      user_id: Base.encode16(user_id, case: :lower),
      challenge: Base.encode16(challenge, case: :lower)
    }

    case send_command(cmd) do
      {:ok, response} ->
        case response do
          %{"credential_id" => cred_id_b64, "public_key" => pub_key_b64} ->
            {:ok,
             %{
               credential_id: Base.decode64!(cred_id_b64),
               public_key: Base.decode64!(pub_key_b64),
               rp_id: "crispkey"
             }}

          %{"error" => error} ->
            {:error, error}
        end

      error ->
        error
    end
  end

  @spec authenticate(binary(), binary(), String.t() | nil) ::
          {:ok, Types.Assertion.t()} | {:error, term()}
  def authenticate(credential_id, challenge, rp_id \\ nil) do
    rp_id = rp_id || "crispkey"

    IO.puts(
      "DEBUG: Port.authenticate - credential_id: #{Base.encode64(credential_id) |> String.slice(0, 30)}..."
    )

    IO.puts("DEBUG: Port.authenticate - challenge length: #{byte_size(challenge)}")
    IO.puts("DEBUG: Port.authenticate - rp_id: #{rp_id}")

    # credential_id might already be Base64 string (if from WrappedKey), so don't re-encode
    cred_id_b64 =
      if is_binary(credential_id) and String.contains?(credential_id, "==") do
        credential_id
      else
        Base.encode64(credential_id)
      end

    cmd = %{
      action: "authenticate",
      credential_id: cred_id_b64,
      challenge: Base.encode64(challenge),
      rp_id: rp_id
    }

    IO.puts("DEBUG: Port.authenticate - sending command to Python shim")

    case send_command(cmd) do
      {:ok, response} ->
        IO.puts("DEBUG: Port.authenticate - response: #{inspect(response)}")

        case response do
          %{
            "auth_data" => auth_data_b64,
            "signature" => sig_b64,
            "client_data_json" => client_json
          } ->
            {:ok,
             %Types.Assertion{
               credential_id: credential_id,
               auth_data: Base.decode64!(auth_data_b64),
               signature: Base.decode64!(sig_b64),
               client_data_json: client_json
             }}

          %{"error" => error} ->
            IO.puts("DEBUG: Port.authenticate - error in response: #{error}")
            {:error, error}
        end

      error ->
        IO.puts("DEBUG: Port.authenticate - send_command error: #{inspect(error)}")
        error
    end
  end

  @spec credential_info(binary(), String.t() | nil) :: {:ok, map()} | {:error, term()}
  def credential_info(credential_id, rp_id \\ nil) do
    rp_id = rp_id || "crispkey"

    cmd = %{
      action: "credential_info",
      credential_id: Base.encode16(credential_id, case: :lower),
      rp_id: rp_id
    }

    send_command(cmd)
  end
end
