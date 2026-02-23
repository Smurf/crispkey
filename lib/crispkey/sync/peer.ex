defmodule Crispkey.Sync.Peer do
  @moduledoc """
  Per-connection GenServer handling the server side of sync.
  """

  use GenServer

  alias Crispkey.Sync.{Message, Protocol}

  alias Crispkey.Sync.Message.{
    Hello,
    Auth,
    Inventory,
    Request,
    KeyData,
    TrustData,
    Ack,
    Goodbye
  }

  @type state :: %{
          socket: :gen_tcp.socket(),
          is_client: boolean(),
          peer_id: String.t() | nil,
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

  @spec send_msg(pid(), Message.t()) :: :ok
  def send_msg(pid, msg) do
    GenServer.cast(pid, {:send, msg})
  end

  @impl true
  @spec init({:gen_tcp.socket(), keyword()}) :: {:ok, state(), {:continue, :handshake}}
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
    case exchange_inventory(state) do
      {:ok, remote_keys, state} ->
        local_keys = get_local_inventory()

        needed = find_needed_keys(local_keys, remote_keys)

        result =
          Enum.reduce(needed, :ok, fn fingerprint, _acc ->
            request_key(state, fingerprint)
          end)

        {:reply, result, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast({:send, msg}, state) do
    data = Protocol.encode(msg)
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

  @spec send_hello(state()) :: :ok
  defp send_hello(state) do
    msg = Protocol.hello(Crispkey.device_id())
    data = Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
  end

  @spec client_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp client_handshake(state) do
    send_hello(state)

    case recv_message(state) do
      {:ok, %Hello{device_id: device_id}, state} ->
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec server_handshake(state()) :: {:ok, state()} | {:error, term()}
  defp server_handshake(state) do
    case recv_message(state) do
      {:ok, %Hello{device_id: device_id}, state} ->
        send_hello(state)
        :inet.setopts(state.socket, [{:active, true}])
        {:ok, %{state | peer_id: device_id}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec handle_message(Message.t(), state()) :: state()
  defp handle_message(%Hello{device_id: device_id}, state) do
    %{state | peer_id: device_id}
  end

  defp handle_message(%Auth{password_hash: hash}, state) do
    IO.puts("[PEER] Received auth request")

    if Crispkey.Store.LocalState.verify_sync_password_hash(hash) do
      IO.puts("[PEER] Auth succeeded")
      msg = Protocol.auth_ok()
      :gen_tcp.send(state.socket, Protocol.encode(msg))
      %{state | authenticated: true}
    else
      IO.puts("[PEER] Auth failed")
      msg = Protocol.auth_fail()
      :gen_tcp.send(state.socket, Protocol.encode(msg))
      state
    end
  end

  defp handle_message(%Inventory{keys: remote_keys}, state) do
    IO.puts("[PEER] Received inventory with #{length(remote_keys)} keys")
    local_keys = get_local_inventory()
    IO.puts("[PEER] Sending back #{length(local_keys)} keys")
    msg = Protocol.inventory(local_keys)
    data = Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)
    state
  end

  defp handle_message(%Request{fingerprints: fps, types: types}, state) do
    IO.puts(
      "[PEER] Received request for #{length(fps)} keys, authenticated=#{state.authenticated}"
    )

    if state.authenticated do
      Enum.each(fps, fn fp ->
        IO.puts("[PEER] Sending key #{fp}")
        send_key(state.socket, fp, types)
      end)

      msg = Protocol.ack("request", :done)
      :gen_tcp.send(state.socket, Protocol.encode(msg))
    else
      IO.puts("[PEER] Not authenticated, ignoring request")
    end

    state
  end

  defp handle_message(%KeyData{fingerprint: fp, key_type: type, data: data}, state) do
    store_key(fp, type, data)
    Crispkey.Store.LocalState.record_sync(state.peer_id, fp)
    state
  end

  defp handle_message(%TrustData{data: data}, state) do
    store_trust(data)
    state
  end

  defp handle_message(%Ack{}, state), do: state
  defp handle_message(%Goodbye{}, state), do: state
  defp handle_message(_, state), do: state

  @spec recv_message(state()) ::
          {:ok, Message.t(), state()} | {:error, term()}
  defp recv_message(state) do
    case :gen_tcp.recv(state.socket, 4, 5000) do
      {:ok, <<len::32>>} ->
        case :gen_tcp.recv(state.socket, len, 5000) do
          {:ok, data} ->
            case Protocol.decode(<<len::32, data::binary>>) do
              {:ok, msg} -> {:ok, msg, state}
              {:error, reason} -> {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec extract_messages(binary()) ::
          {:ok, [Message.t()], binary()} | {:continue, binary()}
  defp extract_messages(buffer) when byte_size(buffer) < 4 do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, rest::binary>> = buffer) when byte_size(rest) < len do
    {:continue, buffer}
  end

  defp extract_messages(<<len::32, data::binary-size(len), rest::binary>>) do
    case Protocol.decode(<<len::32, data::binary>>) do
      {:ok, msg} ->
        case extract_messages(rest) do
          {:ok, msgs, r} -> {:ok, [msg | msgs], r}
          {:continue, r} -> {:ok, [msg], r}
        end

      {:error, _reason} ->
        {:continue, rest}
    end
  end

  @spec get_local_inventory() :: [map()]
  defp get_local_inventory do
    {:ok, pub_keys} = Crispkey.GPG.Interface.list_public_keys()
    {:ok, sec_keys} = Crispkey.GPG.Interface.list_secret_keys()

    inventory =
      (pub_keys ++ sec_keys)
      |> Enum.map(fn key ->
        %{fingerprint: key.fingerprint, type: key.type, modified: key.created_at}
      end)

    IO.puts(
      "[PEER] Local inventory: #{length(pub_keys)} public + #{length(sec_keys)} secret = #{length(inventory)} total"
    )

    inventory
  end

  @spec exchange_inventory(state()) ::
          {:ok, [map()], state()} | {:error, term()}
  defp exchange_inventory(state) do
    local_keys = get_local_inventory()
    msg = Protocol.inventory(local_keys)
    data = Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)

    case recv_message(state) do
      {:ok, %Inventory{keys: remote_keys}, state} ->
        {:ok, remote_keys, state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec find_needed_keys([map()], [map()]) :: [String.t()]
  defp find_needed_keys(local, remote) do
    local_fps = MapSet.new(local, & &1.fingerprint)
    remote_fps = MapSet.new(remote, & &1.fingerprint)
    MapSet.difference(remote_fps, local_fps) |> MapSet.to_list()
  end

  @spec request_key(state(), String.t()) :: :ok | {:error, :timeout}
  defp request_key(state, fingerprint) do
    msg = Protocol.request([fingerprint], [:public, :secret])
    data = Protocol.encode(msg)
    :gen_tcp.send(state.socket, data)

    receive do
      {:tcp, _, _} -> :ok
    after
      30_000 -> {:error, :timeout}
    end
  end

  @spec send_key(:gen_tcp.socket(), String.t(), [atom()]) :: :ok
  defp send_key(socket, fingerprint, types) do
    Enum.each(types, fn type ->
      type_atom = normalize_key_type(type)

      case export_key(fingerprint, type_atom) do
        {:ok, data} ->
          IO.puts("[PEER] Exported #{type_atom} key, sending #{byte_size(data)} bytes")
          msg = Protocol.key_data(fingerprint, type_atom, data, %{})
          :gen_tcp.send(socket, Protocol.encode(msg))

        {:error, reason} ->
          IO.puts("[PEER] Failed to export #{type_atom}: #{inspect(reason)}")
          :ok
      end
    end)
  end

  @spec normalize_key_type(atom() | String.t()) :: atom()
  defp normalize_key_type(type) when is_atom(type), do: type
  defp normalize_key_type(type) when is_binary(type), do: String.to_atom(type)

  @spec export_key(String.t(), :public | :secret) :: {:ok, String.t()} | {:error, term()}
  defp export_key(fingerprint, :public) do
    Crispkey.GPG.Interface.export_public_key(fingerprint)
  end

  defp export_key(fingerprint, :secret) do
    Crispkey.GPG.Interface.export_secret_key(fingerprint)
  end

  defp export_key(_fingerprint, _), do: {:error, :unknown_type}

  @spec store_key(String.t(), atom(), String.t()) :: :ok
  defp store_key(_fingerprint, type, data) do
    type_atom = normalize_key_type(type)

    case Crispkey.GPG.Interface.import_key(data) do
      {:ok, _} -> IO.puts("[PEER] Imported #{type_atom} key")
      {:error, reason} -> IO.puts("[PEER] Failed to import: #{inspect(reason)}")
    end

    :ok
  end

  @spec store_trust(String.t()) :: :ok
  defp store_trust(data) do
    {:ok, _} = Crispkey.GPG.Interface.import_trustdb(data)
    :ok
  end
end
