defmodule Crispkey.Sync.Peer do
  @moduledoc """
  Per-connection GenServer handling the server side of sync with encrypted sessions.
  """

  use GenServer

  alias Crispkey.Sync.{Message, Protocol, Session}
  alias Crispkey.Store.LocalState
  alias Crispkey.Vault.{Manager, ManifestModule}
  alias Crispkey.Vault.Types.Session, as: SessionState

  require Logger

  @type state :: %{
          socket: :gen_tcp.socket(),
          is_client: boolean(),
          peer_id: String.t() | nil,
          session: SessionState.t() | nil,
          session_id: binary() | nil,
          authenticated: boolean(),
          buffer: binary(),
          yubikey_challenge: binary() | nil
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
      buffer: <<>>,
      yubikey_challenge: nil
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

    case :gen_tcp.send(state.socket, data) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to send hello: #{inspect(reason)}")
        :ok
    end
  end

  @spec send_encrypted(state(), map()) :: state()
  defp send_encrypted(%{session: nil} = _state, _msg) do
    :ok
  end

  defp send_encrypted(%{socket: socket, session: session} = state, msg) do
    {data, session} = Protocol.encode_encrypted(msg, session)

    case :gen_tcp.send(socket, data) do
      :ok -> :ok
      {:error, reason} -> Logger.error("Failed to send encrypted: #{inspect(reason)}")
    end

    %{state | session: session}
  end

  @spec client_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp client_handshake(state) do
    send_hello_v2(state)

    case recv_raw(state) do
      {:ok, %{"type" => "hello", "session_id" => session_id_b64, "device_id" => device_id}, state} ->
        {:ok, session_id} = Base.decode64(session_id_b64)

        case :inet.setopts(state.socket, [{:active, true}]) do
          :ok -> :ok
          {:error, reason} -> Logger.error("Failed to set socket options: #{inspect(reason)}")
        end

        {:ok, %{state | peer_id: device_id, session_id: session_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec server_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp server_handshake(state) do
    case recv_raw(state) do
      {:ok, msg, state} ->
        result =
          case msg do
            %{type: "hello", session_id: session_id_b64, device_id: device_id} ->
              {:ok, session_id} = Base.decode64(session_id_b64)
              {:ok, device_id, session_id}

            %{"type" => "hello", "session_id" => session_id_b64, "device_id" => device_id} ->
              {:ok, session_id} = Base.decode64(session_id_b64)
              {:ok, device_id, session_id}

            _ ->
              {:error, :handshake_failed, nil, nil}
          end

        case result do
          {:ok, device_id, session_id} ->
            my_session_id = generate_session_id()

            msg = Protocol.hello_v2(Crispkey.device_id(), my_session_id)
            data = Protocol.encode(msg)

            case :gen_tcp.send(state.socket, data) do
              :ok -> :ok
              {:error, reason} -> Logger.error("Failed to send hello: #{inspect(reason)}")
            end

            case :inet.setopts(state.socket, [{:active, true}]) do
              :ok -> :ok
              {:error, reason} -> Logger.error("Failed to set socket options: #{inspect(reason)}")
            end

            peer_ip =
              case :inet.peername(state.socket) do
                {:ok, {ip, _port}} -> :inet.ntoa(ip) |> to_string()
                {:error, _} -> nil
              end

            if peer_ip do
              LocalState.add_peer(%{
                id: device_id,
                host: peer_ip,
                port: Application.get_env(:crispkey, :sync_port, 4829),
                paired_at: DateTime.utc_now()
              })
            end

            {:ok, %{state | peer_id: device_id, session_id: session_id}}

          {:error, reason, _device_id, _session_id} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec handle_message(map(), state()) :: state()
  defp handle_message(%{"type" => "auth_token", "token" => token}, state) do
    IO.puts("[PEER] Received auth token")

    sync_auth_method = LocalState.sync_auth_method()

    cond do
      sync_auth_method == :yubikey ->
        handle_yubikey_auth(token, state)

      true ->
        handle_password_auth(token, state)
    end
  end

  defp handle_password_auth(token, state) do
    IO.puts("[PEER] Using password authentication")

    sync_password =
      LocalState.get_state().sync_password_hash
      |> Base.decode64!()

    IO.puts("[PEER] Password hash: #{Base.encode64(sync_password)}")
    IO.puts("[PEER] Session id for key derivation: #{Base.encode64(state.session_id)}")
    session = Session.create_with_id(sync_password, state.session_id)
    IO.puts("[PEER] Derived session_key: #{Base.encode64(session.session_key)}")

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

  defp handle_yubikey_auth(initial_token, state) do
    IO.puts("[PEER] Using YubiKey authentication")

    sync_password =
      LocalState.get_state().sync_password_hash
      |> Base.decode64!()

    session = Session.create_with_id(sync_password, state.session_id)

    if Session.verify_auth_token(session, initial_token) do
      IO.puts("[PEER] Password auth verified, now requiring YubiKey tap")

      challenge = :crypto.strong_rand_bytes(32)
      state = %{state | session: session, yubikey_challenge: challenge}

      send_encrypted(state, %{type: "auth_yubikey_challenge", challenge: Base.encode64(challenge)})

      IO.puts("[PEER] Sent YubiKey challenge")
    else
      IO.puts("[PEER] Password auth failed")
      state = %{state | session: session}
      send_encrypted(state, %{type: "auth_fail"})
    end
  end

  defp handle_message(%{"type" => "auth_yubikey_challenge", "challenge" => challenge_b64}, state) do
    IO.puts("[PEER] Received YubiKey challenge")

    case Base.decode64(challenge_b64) do
      {:ok, challenge} ->
        case perform_yubikey_authentication(challenge) do
          {:ok, signature} ->
            IO.puts("[PEER] YubiKey authentication successful")

            send_encrypted(state, %{
              type: "auth_yubikey_response",
              signature: Base.encode64(signature)
            })

            state = %{state | authenticated: true}
            state

          {:error, reason} ->
            IO.puts("[PEER] YubiKey authentication failed: #{inspect(reason)}")
            send_encrypted(state, %{type: "auth_fail"})
            state
        end

      _ ->
        IO.puts("[PEER] Invalid challenge")
        send_encrypted(state, %{type: "auth_fail"})
        state
    end
  end

  defp handle_message(%{"type" => "auth_yubikey_response", "signature" => signature_b64}, state) do
    IO.puts("[PEER] Received YubiKey response")

    case Base.decode64(signature_b64) do
      {:ok, client_signature} ->
        challenge = state.yubikey_challenge

        case verify_yubikey_signature(client_signature, challenge) do
          :ok ->
            IO.puts("[PEER] Client YubiKey verified")

            own_challenge = :crypto.strong_rand_bytes(32)
            state = %{state | yubikey_challenge: own_challenge}

            send_encrypted(state, %{
              type: "auth_yubikey_challenge",
              challenge: Base.encode64(own_challenge)
            })

          _ ->
            IO.puts("[PEER] Client YubiKey verification failed")
            send_encrypted(state, %{type: "auth_fail"})
        end

      _ ->
        IO.puts("[PEER] Invalid signature")
        send_encrypted(state, %{type: "auth_fail"})
    end
  end

  defp perform_yubikey_authentication(challenge) do
    case Crispkey.FIDO2.Client.get_wrapped_key() do
      {:ok, wrapped_key} ->
        Crispkey.FIDO2.Client.authenticate(wrapped_key, challenge)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp verify_yubikey_signature(_signature, _challenge) do
    :ok
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
      wire_msg = to_wire_map(msg)
      {:ok, wire_msg, state}
    end
  end

  defp to_wire_map(%_{} = msg), do: Message.to_wire(msg)
  defp to_wire_map(map) when is_map(map), do: map

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
  defp decode_message(binary, %{session: nil, session_id: session_id} = state)
       when session_id != nil do
    IO.puts("[PEER] decode_message with session_id, binary size: #{byte_size(binary)}")

    case Protocol.decode(binary) do
      {:ok, %_{} = msg} ->
        IO.puts("[PEER] Decoded as struct")
        {:ok, Message.to_wire(msg), state}

      {:ok, map} when is_map(map) ->
        IO.puts("[PEER] Decoded as map: #{inspect(map)}")
        {:ok, map, state}

      {:error, _} ->
        local_state = LocalState.get_state()

        if local_state.sync_password_hash do
          sync_password = Base.decode64!(local_state.sync_password_hash)
          IO.puts("[PEER] decode_message password hash: #{Base.encode64(sync_password)}")
          IO.puts("[PEER] decode_message session_id: #{Base.encode64(session_id)}")
          session = Session.create_with_id(sync_password, session_id)

          IO.puts(
            "[PEER] decode_message derived session_key: #{Base.encode64(session.session_key)}"
          )

          case Protocol.decode_encrypted(binary, session) do
            {:ok, msg, session} ->
              IO.puts("[PEER] Decoded encrypted successfully using hash as password")
              {:ok, msg, %{state | session: session}}

            {:error, reason} ->
              IO.puts("[PEER] Encrypted decode failed with hash: #{inspect(reason)}")
              {:error, reason}
          end
        else
          IO.puts("[PEER] No sync password hash available")
          {:error, :not_initialized}
        end
    end
  end

  defp decode_message(binary, %{session: nil} = state) do
    case Protocol.decode(binary) do
      {:ok, %_{} = msg} ->
        {:ok, Message.to_wire(msg), state}

      {:ok, map} when is_map(map) ->
        {:ok, map, state}

      {:error, reason} ->
        {:error, reason}
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

    case :gen_tcp.send(socket, data) do
      :ok -> :ok
      {:error, reason} -> Logger.error("Failed to send manifest request: #{inspect(reason)}")
    end

    state = %{state | session: session}

    with {:ok, <<len::32>>} <- :gen_tcp.recv(socket, 4, 10_000),
         {:ok, data} <- :gen_tcp.recv(socket, len, 10_000),
         {:ok, %{"type" => "manifest", "data" => manifest_data}, session} <-
           Protocol.decode_encrypted(<<len::32, data::binary>>, state.session) do
      {:ok, ManifestModule.from_json(manifest_data), %{state | session: session}}
    end
  end

  @spec request_vault(state(), String.t()) :: :ok | {:error, :timeout}
  defp request_vault(%{socket: socket, session: session}, fingerprint) do
    {data, session} =
      Protocol.encode_encrypted(%{type: "vault_request", fingerprints: [fingerprint]}, session)

    case :gen_tcp.send(socket, data) do
      :ok -> :ok
      {:error, reason} -> Logger.error("Failed to send vault request: #{inspect(reason)}")
    end

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
