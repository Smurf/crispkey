defmodule Crispkey.Sync.Connection do
  @moduledoc """
  Direct peer connection without requiring daemon.
  """

  def connect(host, port \\ nil) do
    port = port || Application.get_env(:crispkey, :sync_port, 4829)
    
    case :gen_tcp.connect(String.to_charlist(host), port, [:binary, {:active, false}], 5000) do
      {:ok, socket} ->
        handshake(socket)
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp handshake(socket) do
    msg = Crispkey.Sync.Protocol.hello(Crispkey.device_id())
    data = Crispkey.Sync.Protocol.encode(msg)
    :gen_tcp.send(socket, data)
    
    case recv_message(socket) do
      {:ok, %{type: "hello", device_id: device_id}} ->
        {:ok, %{socket: socket, peer_id: device_id}}
      
      {:error, reason} ->
        :gen_tcp.close(socket)
        {:error, reason}
    end
  end

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

  defp authenticate(socket, password) do
    hash = :crypto.hash(:sha256, password) |> Base.encode64()
    msg = Crispkey.Sync.Protocol.auth(hash)
    :gen_tcp.send(socket, Crispkey.Sync.Protocol.encode(msg))
    
    case recv_message(socket) do
      {:ok, %{type: "auth_ok"}} -> :ok
      {:ok, %{type: "auth_fail"}} -> {:error, :auth_failed}
      {:error, reason} -> {:error, reason}
    end
  end

  defp exchange_inventory(socket) do
    local_keys = get_local_inventory()
    msg = Crispkey.Sync.Protocol.inventory(local_keys)
    :gen_tcp.send(socket, Crispkey.Sync.Protocol.encode(msg))
    
    case recv_message(socket) do
      {:ok, %{type: "inventory", keys: remote_keys}} ->
        {:ok, remote_keys}
      {:error, reason} ->
        {:error, reason}
    end
  end

  def close(%{socket: socket}) do
    :gen_tcp.close(socket)
  end

  defp recv_message(socket) do
    case :gen_tcp.recv(socket, 4, 5000) do
      {:ok, <<len::32>>} ->
        case :gen_tcp.recv(socket, len, 5000) do
          {:ok, data} ->
            Crispkey.Sync.Protocol.decode(<<len::32, data::binary>>)
          error -> error
        end
      error -> error
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

  defp find_needed_keys(local, remote) do
    local_fps = MapSet.new(local, & &1.fingerprint)
    remote_fps = MapSet.new(remote, & &1.fingerprint)
    MapSet.difference(remote_fps, local_fps) |> MapSet.to_list()
  end

  defp request_key(socket, fingerprint) do
    msg = Crispkey.Sync.Protocol.request([fingerprint], [:public, :secret])
    :gen_tcp.send(socket, Crispkey.Sync.Protocol.encode(msg))
    
    receive_key_data(socket, 2)
  end

  defp receive_key_data(_socket, 0), do: :ok

  defp receive_key_data(socket, count) do
    case recv_message(socket) do
      {:ok, %{type: "key_data", fingerprint: fp, key_type: type, data: data}} ->
        IO.puts("Received key_data for #{fp}, type=#{type}, #{byte_size(data)} bytes")
        store_key(type, data)
        receive_key_data(socket, count - 1)
      {:error, reason} ->
        IO.puts("Error receiving key data: #{inspect(reason)}")
        :ok
    end
  end

  defp store_key(type, data) do
    type_atom = if is_binary(type), do: String.to_atom(type), else: type
    case Crispkey.GPG.Interface.import_key(data) do
      {:ok, _} -> 
        IO.puts("Imported #{type_atom} key successfully")
        :ok
      {:error, reason} ->
        IO.puts("Failed to import #{type_atom} key: #{inspect(reason)}")
        :ok
    end
  end
end
