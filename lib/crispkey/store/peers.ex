defmodule Crispkey.Store.Peers do
  @moduledoc """
  Cache for discovered peers.
  """

  @peers_file "discovered_peers.json"

  def save(peers) do
    path = peers_path()
    File.mkdir_p!(Path.dirname(path))
    
    data = peers
    |> Enum.map(fn peer -> %{
      id: peer.id,
      port: peer.port,
      ip: Map.get(peer, :ip),
      discovered_at: DateTime.utc_now() |> DateTime.to_iso8601()
    } end)
    |> Jason.encode!(pretty: true)
    
    File.write!(path, data)
  end

  def load do
    path = peers_path()
    
    case File.read(path) do
      {:ok, data} ->
        case Jason.decode(data, keys: :atoms) do
          {:ok, peers} -> peers
          _ -> []
        end
      _ -> []
    end
  end

  def find(device_id) do
    load()
    |> Enum.find(fn peer -> peer.id == device_id end)
  end

  defp peers_path do
    Path.join(Crispkey.data_dir(), @peers_file)
  end
end
