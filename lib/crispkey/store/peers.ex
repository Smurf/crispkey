defmodule Crispkey.Store.Peers do
  @moduledoc """
  Cache for discovered peers.
  """

  @peers_file "discovered_peers.json"

  @type discovered_peer :: %{
          id: String.t(),
          port: non_neg_integer(),
          ip: String.t() | nil,
          discovered_at: String.t() | nil
        }

  @spec save([discovered_peer()]) :: :ok
  def save(peers) do
    path = peers_path()
    File.mkdir_p!(Path.dirname(path))

    data =
      peers
      |> Enum.map(fn peer ->
        %{
          id: peer.id,
          port: peer.port,
          ip: Map.get(peer, :ip),
          discovered_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }
      end)
      |> Jason.encode!(pretty: true)

    File.write!(path, data)
    :ok
  end

  @spec load() :: [discovered_peer()]
  def load do
    path = peers_path()

    case File.read(path) do
      {:ok, data} ->
        case Jason.decode(data) do
          {:ok, peers} when is_list(peers) ->
            Enum.map(peers, &parse_peer/1)

          _ ->
            []
        end

      _ ->
        []
    end
  end

  @spec find(String.t()) :: discovered_peer() | nil
  def find(device_id) do
    load()
    |> Enum.find(fn peer -> peer.id == device_id end)
  end

  @spec parse_peer(map()) :: discovered_peer()
  defp parse_peer(data) do
    %{
      id: Map.get(data, "id"),
      port: Map.get(data, "port"),
      ip: Map.get(data, "ip"),
      discovered_at: Map.get(data, "discovered_at")
    }
  end

  @spec peers_path() :: String.t()
  defp peers_path do
    Path.join(Crispkey.data_dir(), @peers_file)
  end
end
