defmodule Crispkey.Sync.Connection do
  @moduledoc """
  Encrypted peer connection for vault sync.

  ## Protocol v2

  All communication after the initial HELLO is encrypted with a
  session key derived from the sync password.

  ## Sync Flow

  1. Connect and exchange HELLO with session IDs
  2. Authenticate with HMAC-based auth token
  3. Exchange manifests to determine needed vaults
  4. Transfer encrypted vault files
  """

  alias Crispkey.Sync.{Protocol, Session}
  alias Crispkey.Vault.{Manager, ManifestModule}
  alias Crispkey.Vault.Types.Session, as: SessionState

  @type connection :: %{
          socket: :gen_tcp.socket(),
          peer_id: String.t(),
          session: SessionState.t() | nil
        }

  @spec connect(String.t(), non_neg_integer() | nil) :: {:ok, connection()} | {:error, term()}
  def connect(host, port \\ nil) do
    port = port || Application.get_env(:crispkey, :sync_port, 4829)

    case :gen_tcp.connect(String.to_charlist(host), port, [:binary, {:active, false}], 5000) do
      {:ok, socket} ->
        handshake(socket)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec handshake(:gen_tcp.socket()) :: {:ok, connection()} | {:error, term()}
  defp handshake(socket) do
    msg = Protocol.hello_v2(Crispkey.device_id(), generate_session_id())
    data = Protocol.encode(msg)
    :gen_tcp.send(socket, data)

    case recv_raw(socket) do
      {:ok, %{"type" => "hello", "device_id" => device_id, "session_id" => session_id_b64}} ->
        session_id = Base.decode64!(session_id_b64)
        {:ok, %{socket: socket, peer_id: device_id, session_id: session_id}}

      {:ok, %{"type" => "hello", "device_id" => device_id}} ->
        {:ok, %{socket: socket, peer_id: device_id, session: nil}}

      {:error, reason} ->
        :gen_tcp.close(socket)
        {:error, reason}
    end
  end

  @spec sync(connection(), String.t()) :: :ok | {:error, term()}
  def sync(conn, sync_password) do
    session = Session.create_with_id(sync_password, conn.session_id)
    conn = %{conn | session: session}

    with :ok <- authenticate(conn),
         {:ok, remote_manifest} <- exchange_manifest(conn) do
      {:ok, local_manifest} = Manager.get_manifest()

      IO.puts("Local vaults: #{map_size(local_manifest.vaults)}")
      IO.puts("Remote vaults: #{map_size(remote_manifest.vaults)}")

      diff = ManifestModule.diff(local_manifest, remote_manifest)
      needed = Enum.map(diff.remote_only, & &1.fingerprint)

      IO.puts("Vaults to fetch: #{length(needed)}")

      Enum.each(needed, fn fingerprint ->
        IO.puts("Requesting vault: #{fingerprint}")
        request_vault(conn, fingerprint)
      end)

      :ok
    else
      {:error, reason} = err ->
        IO.puts("Sync error: #{inspect(reason)}")
        err
    end
  end

  @spec authenticate(connection()) :: :ok | {:error, term()}
  defp authenticate(%{socket: socket, session: session} = _conn) do
    auth_token = Session.compute_auth_token(session)
    msg = Protocol.auth_token(auth_token)

    {data, _} = Protocol.encode_encrypted(msg, session)
    :gen_tcp.send(socket, data)

    case recv_encrypted(socket, session) do
      {:ok, %{"type" => "auth_ok"}, _} -> :ok
      {:ok, %{"type" => "auth_fail"}, _} -> {:error, :auth_failed}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec exchange_manifest(connection()) :: {:ok, map()} | {:error, term()}
  defp exchange_manifest(%{socket: socket, session: session} = _conn) do
    msg = Protocol.manifest_request()
    {data, session} = Protocol.encode_encrypted(msg, session)
    :gen_tcp.send(socket, data)

    case recv_encrypted(socket, session) do
      {:ok, %{"type" => "manifest", "data" => manifest_data}, _} ->
        {:ok, ManifestModule.from_json(manifest_data)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec request_vault(connection(), String.t()) :: :ok
  defp request_vault(%{socket: socket, session: session} = conn, fingerprint) do
    msg = Protocol.vault_request([fingerprint])
    {data, session} = Protocol.encode_encrypted(msg, session)
    :gen_tcp.send(socket, data)

    receive_vault_data(conn, fingerprint, session)
  end

  @spec receive_vault_data(connection(), String.t(), SessionState.t()) :: :ok
  defp receive_vault_data(%{socket: socket} = _conn, expected_fp, session) do
    case recv_encrypted(socket, session) do
      {:ok, %{"type" => "vault_data", "fingerprint" => fp, "data" => data_b64}, session} ->
        if fp == expected_fp do
          vault_data = Base.decode64!(data_b64)
          :ok = Manager.put_raw_vault(fp, vault_data)
          IO.puts("Received and stored vault: #{fp}")
          :ok
        else
          IO.puts("Unexpected vault fingerprint: #{fp}")
          receive_vault_data(%{socket: socket}, expected_fp, session)
        end

      {:ok, %{"type" => "ack"}, _} ->
        IO.puts("No more vaults")
        :ok

      {:ok, other, _} ->
        IO.puts("Unexpected message: #{inspect(other)}")
        :ok

      {:error, :timeout} ->
        IO.puts("Timeout waiting for vault data")
        :ok

      {:error, reason} ->
        IO.puts("Error receiving vault: #{inspect(reason)}")
        :ok
    end
  end

  @spec close(connection()) :: :ok
  def close(%{socket: socket}) do
    :gen_tcp.close(socket)
  end

  @spec recv_raw(:gen_tcp.socket(), non_neg_integer()) :: {:ok, map()} | {:error, term()}
  defp recv_raw(socket, timeout \\ 5000) do
    case :gen_tcp.recv(socket, 4, timeout) do
      {:ok, <<len::32>>} ->
        case :gen_tcp.recv(socket, len, 5000) do
          {:ok, data} ->
            Protocol.decode(<<len::32, data::binary>>)

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec recv_encrypted(:gen_tcp.socket(), SessionState.t(), non_neg_integer()) ::
          {:ok, map(), SessionState.t()} | {:error, term()}
  defp recv_encrypted(socket, session, timeout \\ 10_000) do
    case :gen_tcp.recv(socket, 4, timeout) do
      {:ok, <<len::32>>} ->
        case :gen_tcp.recv(socket, len, timeout) do
          {:ok, data} ->
            Protocol.decode_encrypted(<<len::32, data::binary>>, session)

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :timeout} ->
        {:error, :timeout}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec generate_session_id() :: binary()
  defp generate_session_id do
    :crypto.strong_rand_bytes(16)
  end
end
