defmodule Crispkey.Sync.Peer do
  @moduledoc """
  Per-connection GenServer handling the server side of sync with encrypted sessions.
  """

  use GenServer

  alias Crispkey.Sync.{Protocol, Session}
  alias Crispkey.Store.LocalState
  alias Crispkey.Vault.{Manager, ManifestModule}
  alias Crispkey.Vault.Types.Session, as: SessionState

  @type state :: %{
          socket: :gen_tcp.socket(),
          is_client: boolean(),
          peer_id: String.t() | nil,
          session: SessionState.t() | nil,
          session_id: binary() | nil,
          authenticated: boolean(),
          buffer: binary()
        }

  @spec start(:gen_tcp.socket(), keyword()) :: GenServer.on_start()
  def start(socket, opts \\ []) do
    GenServer.start(__MODULE__, {socket, opts})
  end

  @spec sync(String.t()) :: :ok | {:error, term()}
  def sync(peer_id) do
    case Process.whereis(:"peer_#{peer_id}") do
      nil -> {:error, :not_connected}
      pid -> GenServer.call(pid, :sync, 60_000)
    end
  end

  @impl true
  @spec init({:gen_tcp.socket(), keyword()}) :: {:ok, state(), {:continue, :handshake}}
  def init({socket, opts}) do
    state = %{
      socket: socket,
      is_client: Keyword.get(opts, :is_client, false),
      peer_id: nil,
      session: nil,
      session_id: nil,
      authenticated: false,
      buffer: <<>>
    }

    {:ok, state, {:continue, :handshake}}
  end

  @impl true
  def handle_continue(:handshake, state) do
    result =
      if state.is_client do
        client_handshake(state)
      else
        server_handshake(state)
      end

    case result do
      {:ok, state} -> {:noreply, state}
      {:error, _reason} -> {:stop, :handshake_failed, state}
    end
  end

  @impl true
  def handle_call(:sync, _from, state) do
    case exchange_manifest(state) do
      {:ok, remote_manifest, state} ->
        {:ok, local_manifest} = Manager.get_manifest()

        diff = ManifestModule.diff(local_manifest, remote_manifest)
        needed = Enum.map(diff.remote_only, & &1.fingerprint)

        result =
          Enum.reduce(needed, :ok, fn fingerprint, _acc ->
            request_vault(state, fingerprint)
          end)

        {:reply, result, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({:tcp, _socket, data}, state) do
    buffer = state.buffer <> data

    case extract_messages(buffer, state) do
      {:ok, messages, rest, state} ->
        state = Enum.reduce(messages, state, &handle_message/2)
        {:noreply, %{state | buffer: rest}}

      {:continue, rest} ->
        {:noreply, %{state | buffer: rest}}
    end
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:stop, :normal, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @spec send_hello_v2(state()) :: :ok
  defp send_hello_v2(state) do
    session_id = generate_session_id()
    msg = Protocol.hello_v2(Crispkey.device_id(), session_id)
    data = Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    :ok
  end

  @spec send_encrypted(state(), map()) :: state()
  defp send_encrypted(%{session: nil} = _state, _msg) do
    :ok
  end

  defp send_encrypted(%{socket: socket, session: session} = state, msg) do
    {data, session} = Protocol.encode_encrypted(msg, session)
    :gen_tcp.send(socket, data)
    %{state | session: session}
  end

  @spec client_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp client_handshake(state) do
    send_hello_v2(state)

    case recv_raw(state) do
      {:ok, %{"type" => "hello", "device_id" => device_id, "session_id" => session_id_b64}, state} ->
        session_id = Base.decode64!(session_id_b64)
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id, session_id: session_id}}

      {:ok, %{"type" => "hello", "device_id" => device_id}, state} ->
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec server_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp server_handshake(state) do
    case recv_raw(state) do
      {:ok, %{"type" => "hello", "device_id" => device_id, "session_id" => session_id_b64}, state} ->
        session_id = Base.decode64!(session_id_b64)
        my_session_id = generate_session_id()

        msg = Protocol.hello_v2(Crispkey.device_id(), my_session_id)
        data = Protocol.encode(msg)
        :gen_tcp.send(state.socket, data)

        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id, session_id: session_id}}

      {:ok, %{"type" => "hello", "device_id" => device_id}, state} ->
        msg = Protocol.hello(Crispkey.device_id())
        data = Protocol.encode(msg)
        :gen_tcp.send(state.socket, data)

        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec handle_message(map(), state()) :: state()
  defp handle_message(%{"type" => "auth_token", "token" => token}, state) do
    IO.puts("[PEER] Received auth token")

    sync_password =
      LocalState.get_state().sync_password_hash
      |> Base.decode64!()

    session = Session.create_with_id(sync_password, state.session_id)

    if Session.verify_auth_token(session, token) do
      IO.puts("[PEER] Auth succeeded")
      state = %{state | session: session, authenticated: true}
      send_encrypted(state, %{type: "auth_ok"})
    else
      IO.puts("[PEER] Auth failed")
      state = %{state | session: session}
      send_encrypted(state, %{type: "auth_fail"})
    end
  end

  defp handle_message(%{"type" => "manifest_request"}, state) do
    IO.puts("[PEER] Received manifest request")

    if state.authenticated do
      {:ok, manifest} = Manager.get_manifest()
      manifest_json = ManifestModule.to_json(manifest)
      send_encrypted(state, %{type: "manifest", data: manifest_json})
    else
      IO.puts("[PEER] Not authenticated, ignoring manifest request")
      state
    end
  end

  defp handle_message(%{"type" => "vault_request", "fingerprints" => fps}, state) do
    IO.puts(
      "[PEER] Received vault request for #{length(fps)} vaults, authenticated=#{state.authenticated}"
    )

    if state.authenticated do
      Enum.each(fps, fn fp ->
        IO.puts("[PEER] Sending vault #{fp}")
        send_vault(state, fp)
      end)

      send_encrypted(state, %{type: "ack"})
    else
      IO.puts("[PEER] Not authenticated, ignoring vault request")
      state
    end
  end

  defp handle_message(%{"type" => "vault_data", "fingerprint" => fp, "data" => data_b64}, state) do
    vault_data = Base.decode64!(data_b64)
    :ok = Manager.put_raw_vault(fp, vault_data)
    IO.puts("[PEER] Stored vault #{fp}")
    state
  end

  defp handle_message(%{"type" => "ack"}, state), do: state
  defp handle_message(_, state), do: state

  @spec recv_raw(state()) :: {:ok, map(), state()} | {:error, term()}
  defp recv_raw(state) do
    with {:ok, <<len::32>>} <- :gen_tcp.recv(state.socket, 4, 5000),
         {:ok, data} <- :gen_tcp.recv(state.socket, len, 5000),
         {:ok, msg} <- Protocol.decode(<<len::32, data::binary>>) do
      {:ok, msg, state}
    end
  end

  @spec extract_messages(binary(), state()) ::
          {:ok, [map()], binary(), state()} | {:continue, binary()}
  defp extract_messages(buffer, _state) when byte_size(buffer) < 4 do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, rest::binary>> = buffer, _state) when byte_size(rest) < len do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, data::binary-size(len), rest::binary>>, state) do
    case decode_message(<<len::32, data::binary>>, state) do
      {:ok, msg, state} ->
        case extract_messages(rest, state) do
          {:ok, msgs, r, state} -> {:ok, [msg | msgs], r, state}
          {:continue, r} -> {:ok, [msg], r, state}
        end

      {:error, _reason} ->
        {:continue, rest}
    end
  end

  @spec decode_message(binary(), state()) :: {:ok, map(), state()} | {:error, term()}
  defp decode_message(binary, %{session: nil} = state) do
    Protocol.decode(binary)
    |> case do
      {:ok, msg} -> {:ok, msg, state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_message(binary, %{session: session} = state) do
    case Protocol.decode_encrypted(binary, session) do
      {:ok, msg, session} -> {:ok, msg, %{state | session: session}}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec exchange_manifest(state()) ::
          {:ok, map(), state()} | {:error, term()}
  defp exchange_manifest(%{session: nil} = _state) do
    {:error, :no_session}
  end

  defp exchange_manifest(%{socket: socket, session: session} = state) do
    {data, session} = Protocol.encode_encrypted(%{type: "manifest_request"}, session)
    :gen_tcp.send(socket, data)
    state = %{state | session: session}

    with {:ok, <<len::32>>} <- :gen_tcp.recv(socket, 4, 10_000),
         {:ok, data} <- :gen_tcp.recv(socket, len, 10_000),
         {:ok, %{"type" => "manifest", "data" => manifest_data}, session} <-
           Protocol.decode_encrypted(<<len::32, data::binary>>, state.session) do
      {:ok, ManifestModule.from_json(manifest_data), %{state | session: session}}
    end
  end

  @spec request_vault(state(), String.t()) :: :ok | {:error, :timeout}
  defp request_vault(%{session: nil}, _fingerprint) do
    {:error, :no_session}
  end

  defp request_vault(%{socket: socket, session: session}, fingerprint) do
    {data, session} =
      Protocol.encode_encrypted(%{type: "vault_request", fingerprints: [fingerprint]}, session)

    :gen_tcp.send(socket, data)

    receive do
      {:tcp, _, _} ->
        case :gen_tcp.recv(socket, 4, 30_000) do
          {:ok, <<len::32>>} ->
            case :gen_tcp.recv(socket, len, 30_000) do
              {:ok, data} ->
                case Protocol.decode_encrypted(<<len::32, data::binary>>, session) do
                  {:ok, %{"type" => "vault_data", "fingerprint" => fp, "data" => data_b64}, _} ->
                    vault_data = Base.decode64!(data_b64)
                    :ok = Manager.put_raw_vault(fp, vault_data)
                    IO.puts("[PEER] Stored vault #{fp}")
                    :ok

                  {:ok, %{"type" => "ack"}, _} ->
                    :ok

                  {:error, reason} ->
                    IO.puts("[PEER] Error decoding vault: #{inspect(reason)}")
                    :ok
                end

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end
    after
      30_000 -> {:error, :timeout}
    end
  end

  @spec send_vault(state(), String.t()) :: state()
  defp send_vault(%{socket: _socket, session: _session} = state, fingerprint) do
    case Manager.get_raw_vault(fingerprint) do
      {:ok, vault_data} ->
        msg = %{type: "vault_data", fingerprint: fingerprint, data: Base.encode64(vault_data)}
        send_encrypted(state, msg)

      {:error, :not_found} ->
        IO.puts("[PEER] Vault not found: #{fingerprint}")
        state
    end
  end

  @spec generate_session_id() :: binary()
  defp generate_session_id do
    :crypto.strong_rand_bytes(16)
  end
end
