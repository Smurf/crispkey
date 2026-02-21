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
      {:ok, %{type: :hello, device_id: device_id}} ->
        {:ok, %{socket: socket, peer_id: device_id}}
      
      {:error, reason} ->
        :gen_tcp.close(socket)
        {:error, reason}
    end
  end

  def sync(socket) do
    local_keys = get_local_inventory()
    msg = Crispkey.Sync.Protocol.inventory(local_keys)
    :gen_tcp.send(socket, Crispkey.Sync.Protocol.encode(msg))
    
    case recv_message(socket) do
      {:ok, %{type: :inventory, keys: remote_keys}} ->
        needed = find_needed_keys(local_keys, remote_keys)
        
        Enum.each(needed, fn fingerprint ->
          request_key(socket, fingerprint)
        end)
        
        :ok
      
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
    
    receive do
      {:tcp, _, _} -> :ok
    after
      30_000 -> {:error, :timeout}
    end
  end
end
