defmodule Crispkey.Sync.Connection do
  @moduledoc """
  Direct peer connection without requiring daemon.
  """

  alias Crispkey.Sync.{Message, Protocol}
  alias Crispkey.Sync.Message.{Hello, AuthOk, AuthFail, Inventory, KeyData, Ack}

  @type connection :: %{socket: :gen_tcp.socket(), peer_id: String.t()}
  @type inventory_key :: %{fingerprint: String.t(), type: atom(), modified: DateTime.t() | nil}

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
    msg = Protocol.hello(Crispkey.device_id())
    data = Protocol.encode(msg)
    :gen_tcp.send(socket, data)

    case recv_message(socket) do
      {:ok, %Hello{device_id: device_id}} ->
        {:ok, %{socket: socket, peer_id: device_id}}

      {:error, reason} ->
        :gen_tcp.close(socket)
        {:error, reason}
    end
  end

  @spec sync(:gen_tcp.socket(), String.t()) :: :ok | {:error, term()}
  def sync(socket, remote_password) do
    with :ok <- authenticate(socket, remote_password),
         {:ok, remote_keys} <- exchange_inventory(socket) do
      local_keys = get_local_inventory()

      IO.puts("Local keys: #{length(local_keys)}")
      IO.puts("Remote keys: #{length(remote_keys)}")

      needed = find_needed_keys(local_keys, remote_keys)
      IO.puts("Keys to fetch: #{length(needed)}")

      Enum.each(needed, fn fingerprint ->
        IO.puts("Requesting key: #{fingerprint}")
        request_key(socket, fingerprint)
      end)

      :ok
    else
      {:error, reason} = err ->
        IO.puts("Sync error: #{inspect(reason)}")
        err
    end
  end

  @spec authenticate(:gen_tcp.socket(), String.t()) :: :ok | {:error, term()}
  defp authenticate(socket, password) do
    hash = :crypto.hash(:sha256, password) |> Base.encode64()
    msg = Protocol.auth(hash)
    :gen_tcp.send(socket, Protocol.encode(msg))

    case recv_message(socket) do
      {:ok, %AuthOk{}} -> :ok
      {:ok, %AuthFail{}} -> {:error, :auth_failed}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec exchange_inventory(:gen_tcp.socket()) :: {:ok, [inventory_key()]} | {:error, term()}
  defp exchange_inventory(socket) do
    local_keys = get_local_inventory()
    msg = Protocol.inventory(local_keys)
    :gen_tcp.send(socket, Protocol.encode(msg))

    case recv_message(socket) do
      {:ok, %Inventory{keys: remote_keys}} ->
        public_count = Enum.count(remote_keys, fn k -> key_type(k) == :public end)
        secret_count = Enum.count(remote_keys, fn k -> key_type(k) == :secret end)

        IO.puts(
          "Remote inventory: #{public_count} public + #{secret_count} secret = #{length(remote_keys)} total"
        )

        {:ok, remote_keys}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec close(connection()) :: :ok
  def close(%{socket: socket}) do
    :gen_tcp.close(socket)
  end

  @spec recv_message(:gen_tcp.socket(), non_neg_integer()) ::
          {:ok, Message.t()} | {:error, term()}
  defp recv_message(socket, timeout \\ 5000) do
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

  @spec get_local_inventory() :: [inventory_key()]
  defp get_local_inventory do
    {:ok, pub_keys} = Crispkey.GPG.Interface.list_public_keys()
    {:ok, sec_keys} = Crispkey.GPG.Interface.list_secret_keys()

    inventory =
      (pub_keys ++ sec_keys)
      |> Enum.map(fn key ->
        %{fingerprint: key.fingerprint, type: key.type, modified: key.created_at}
      end)

    IO.puts(
      "Local inventory: #{length(pub_keys)} public + #{length(sec_keys)} secret = #{length(inventory)} total"
    )

    inventory
  end

  @spec find_needed_keys([inventory_key()], [inventory_key()]) :: [String.t()]
  defp find_needed_keys(local, remote) do
    local_set = MapSet.new(local, fn k -> {k.fingerprint, key_type(k)} end)
    remote_set = MapSet.new(remote, fn k -> {k.fingerprint, key_type(k)} end)

    diff = MapSet.difference(remote_set, local_set)
    IO.puts("Missing keys: #{inspect(MapSet.to_list(diff))}")

    diff
    |> MapSet.to_list()
    |> Enum.map(fn {fp, _type} -> fp end)
    |> Enum.uniq()
  end

  @spec key_type(map()) :: atom()
  defp key_type(%{type: type}) when is_atom(type), do: type
  defp key_type(%{type: type}) when is_binary(type), do: String.to_atom(type)
  defp key_type(_), do: :unknown

  @spec request_key(:gen_tcp.socket(), String.t()) :: :ok
  defp request_key(socket, fingerprint) do
    msg = Protocol.request([fingerprint], [:public, :secret])
    :gen_tcp.send(socket, Protocol.encode(msg))

    receive_key_data(socket)
  end

  @spec receive_key_data(:gen_tcp.socket()) :: :ok
  defp receive_key_data(socket) do
    case recv_message(socket, 5000) do
      {:ok, %KeyData{fingerprint: fp, key_type: type, data: data}} ->
        IO.puts("Received key_data for #{fp}, type=#{type}, #{byte_size(data)} bytes")
        store_key(type, data)
        receive_key_data(socket)

      {:ok, %Ack{}} ->
        IO.puts("Received ack, done with this key")
        :ok

      {:ok, other} ->
        IO.puts("Received #{inspect(other)}, stopping key receive")
        :ok

      {:error, :timeout} ->
        IO.puts("Timeout waiting for key data")
        :ok

      {:error, reason} ->
        IO.puts("Error receiving key data: #{inspect(reason)}")
        :ok
    end
  end

  @spec store_key(atom(), String.t()) :: :ok
  defp store_key(type, data) do
    case Crispkey.GPG.Interface.import_key(data) do
      {:ok, _} ->
        IO.puts("Imported #{type} key successfully")
        :ok

      {:error, reason} ->
        IO.puts("Failed to import #{type} key: #{inspect(reason)}")
        :ok
    end
  end
end
