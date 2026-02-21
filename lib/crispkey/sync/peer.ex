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

  defp handle_message(%{type: "inventory", keys: _keys}, state) do
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

  defp store_key(_fingerprint, :public, data) do
    {:ok, _} = Crispkey.GPG.Interface.import_key(data)
    :ok
  end

  defp store_key(_fingerprint, :secret, _data) do
    :ok
  end

  defp store_trust(data) do
    {:ok, _} = Crispkey.GPG.Interface.import_trustdb(data)
    :ok
  end
end
