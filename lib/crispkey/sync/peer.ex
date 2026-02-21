defmodule Crispkey.Sync.Peer do
  use GenServer

  def start(socket, opts \\ []) do
    GenServer.start(__MODULE__, {socket, opts})
  end

  def sync(peer_id) do
    case Process.whereis(:"peer_#{peer_id}") do
      nil -> {:error, :not_connected}
      pid -> GenServer.call(pid, :sync, 60_000)
    end
  end

  def send_msg(pid, msg) do
    GenServer.cast(pid, {:send, msg})
  end

  @impl true
  def init({socket, opts}) do
    state = %{
      socket: socket,
      is_client: Keyword.get(opts, :is_client, false),
      peer_id: nil,
      authenticated: false,
      buffer: <<>>
    }
    
    {:ok, state, {:continue, :handshake}}
  end

  @impl true
  def handle_continue(:handshake, state) do
    result = if state.is_client do
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
    case exchange_inventory(state) do
      {:ok, remote_keys, state} ->
        local_keys = get_local_inventory()
        
        needed = find_needed_keys(local_keys, remote_keys)
        
        result = Enum.reduce(needed, :ok, fn fingerprint, _acc ->
          request_key(state, fingerprint)
        end)
        
        {:reply, result, state}
      
      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast({:send, msg}, state) do
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    {:noreply, state}
  end

  @impl true
  def handle_info({:tcp, _socket, data}, state) do
    buffer = state.buffer <> data
    
    case extract_messages(buffer) do
      {:ok, messages, rest} ->
        state = Enum.reduce(messages, state, &handle_message/2)
        {:noreply, %{state | buffer: rest}}
      
      {:continue, rest} ->
        {:noreply, %{state | buffer: rest}}
    end
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:stop, :normal, state}
  end

  def handle_info({:inventory, _keys}, state) do
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp send_hello(state) do
    msg = Crispkey.Sync.Protocol.hello(Crispkey.device_id())
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
  end

  defp client_handshake(state) do
    send_hello(state)
    case recv_message(state) do
      {:ok, %{type: "hello", device_id: device_id}, state} ->
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp server_handshake(state) do
    case recv_message(state) do
      {:ok, %{type: "hello", device_id: device_id}, state} ->
        send_hello(state)
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp handle_message(%{type: "hello", device_id: device_id}, state) do
    %{state | peer_id: device_id}
  end

  defp handle_message(%{type: "auth", password_hash: hash}, state) do
    IO.puts("[PEER] Received auth request")
    if Crispkey.Store.LocalState.verify_sync_password_hash(hash) do
      IO.puts("[PEER] Auth succeeded")
      msg = Crispkey.Sync.Protocol.auth_ok()
      :gen_tcp.send(state.socket, Crispkey.Sync.Protocol.encode(msg))
      %{state | authenticated: true}
    else
      IO.puts("[PEER] Auth failed")
      msg = Crispkey.Sync.Protocol.auth_fail()
      :gen_tcp.send(state.socket, Crispkey.Sync.Protocol.encode(msg))
      state
    end
  end

  defp handle_message(%{type: "inventory", keys: remote_keys}, state) do
    IO.puts("[PEER] Received inventory with #{length(remote_keys)} keys")
    local_keys = get_local_inventory()
    IO.puts("[PEER] Sending back #{length(local_keys)} keys")
    msg = Crispkey.Sync.Protocol.inventory(local_keys)
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    state
  end

  defp handle_message(%{type: "request", fingerprints: fps, types: types}, state) do
    IO.puts("[PEER] Received request for #{length(fps)} keys, authenticated=#{state.authenticated}")
    if state.authenticated do
      Enum.each(fps, fn fp ->
        IO.puts("[PEER] Sending key #{fp}")
        send_key(state.socket, fp, types)
      end)
    else
      IO.puts("[PEER] Not authenticated, ignoring request")
    end
    state
  end

  defp handle_message(%{type: "key_data", fingerprint: fp, key_type: type, data: data}, state) do
    store_key(fp, type, data)
    Crispkey.Store.LocalState.record_sync(state.peer_id, fp)
    state
  end

  defp handle_message(%{type: "trust_data", data: data}, state) do
    store_trust(data)
    state
  end

  defp handle_message(%{type: "ack"}, state), do: state
  defp handle_message(%{type: "goodbye"}, state), do: state
  defp handle_message(_, state), do: state

  defp recv_message(state) do
    case :gen_tcp.recv(state.socket, 4, 5000) do
      {:ok, <<len::32>>} ->
        case :gen_tcp.recv(state.socket, len, 5000) do
          {:ok, data} ->
            case Crispkey.Sync.Protocol.decode(<<len::32, data::binary>>) do
              {:ok, msg} -> {:ok, msg, state}
              :error -> {:error, :decode_error}
            end
          {:error, reason} -> {:error, reason}
        end
      {:error, reason} -> {:error, reason}
    end
  end

  defp extract_messages(buffer) when byte_size(buffer) < 4 do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, rest::binary>> = buffer) when byte_size(rest) < len do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, data::binary-size(len), rest::binary>>) do
    case Crispkey.Sync.Protocol.decode(<<len::32, data::binary>>) do
      {:ok, msg} ->
        case extract_messages(rest) do
          {:ok, msgs, r} -> {:ok, [msg | msgs], r}
          {:continue, r} -> {:ok, [msg], r}
        end
      :error ->
        {:continue, rest}
    end
  end

  defp get_local_inventory do
    {:ok, pub_keys} = Crispkey.GPG.Interface.list_public_keys()
    {:ok, sec_keys} = Crispkey.GPG.Interface.list_secret_keys()
    
    (pub_keys ++ sec_keys)
    |> Enum.map(fn key ->
      %{fingerprint: key.fingerprint, type: key.type, modified: key.created_at}
    end)
  end

  defp exchange_inventory(state) do
    local_keys = get_local_inventory()
    msg = Crispkey.Sync.Protocol.inventory(local_keys)
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    
    case recv_message(state) do
      {:ok, %{type: "inventory", keys: remote_keys}, state} ->
        {:ok, remote_keys, state}
      error -> error
    end
  end

  defp find_needed_keys(local, remote) do
    local_fps = MapSet.new(local, & &1.fingerprint)
    remote_fps = MapSet.new(remote, & &1.fingerprint)
    MapSet.difference(remote_fps, local_fps) |> MapSet.to_list()
  end

  defp request_key(state, fingerprint) do
    msg = Crispkey.Sync.Protocol.request([fingerprint], [:public, :secret])
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    
    receive do
      {:tcp, _, _} -> :ok
    after
      30_000 -> {:error, :timeout}
    end
  end

  defp send_key(socket, fingerprint, types) do
    Enum.each(types, fn type ->
      type_atom = if is_binary(type), do: String.to_atom(type), else: type
      case export_key(fingerprint, type_atom) do
        {:ok, data} ->
          IO.puts("[PEER] Exported #{type_atom} key, sending #{byte_size(data)} bytes")
          msg = Crispkey.Sync.Protocol.key_data(fingerprint, type_atom, data, %{})
          :gen_tcp.send(socket, Crispkey.Sync.Protocol.encode(msg))
        {:error, reason} ->
          IO.puts("[PEER] Failed to export #{type_atom}: #{inspect(reason)}")
          :ok
      end
    end)
  end

  defp export_key(fingerprint, :public) do
    Crispkey.GPG.Interface.export_public_key(fingerprint)
  end

  defp export_key(fingerprint, :secret) do
    Crispkey.GPG.Interface.export_secret_key(fingerprint)
  end

  defp export_key(_fingerprint, _), do: {:error, :unknown_type}

  defp store_key(_fingerprint, type, data) do
    type_atom = if is_binary(type), do: String.to_atom(type), else: type
    case Crispkey.GPG.Interface.import_key(data) do
      {:ok, _} -> IO.puts("[PEER] Imported #{type_atom} key")
      {:error, reason} -> IO.puts("[PEER] Failed to import: #{inspect(reason)}")
    end
    :ok
  end

  defp store_trust(data) do
    {:ok, _} = Crispkey.GPG.Interface.import_trustdb(data)
    :ok
  end
end
