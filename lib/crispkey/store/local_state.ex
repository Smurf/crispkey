defmodule Crispkey.Store.LocalState do
  @moduledoc """
  Persistent state GenServer backed by `~/.config/crispkey/state.json`.
  """

  use GenServer

  alias Crispkey.Store.{Peer, State}

  @type state :: State.t()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @spec get_state() :: state()
  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  @spec update_state((state() -> state())) :: :ok
  def update_state(fun) do
    GenServer.call(__MODULE__, {:update_state, fun})
  end

  @spec add_peer(Peer.t() | map()) :: :ok
  def add_peer(peer) do
    GenServer.call(__MODULE__, {:add_peer, peer})
  end

  @spec remove_peer(String.t()) :: :ok
  def remove_peer(peer_id) do
    GenServer.call(__MODULE__, {:remove_peer, peer_id})
  end

  @spec get_peers() :: [Peer.t()]
  def get_peers do
    GenServer.call(__MODULE__, :get_peers)
  end

  @spec record_sync(String.t(), String.t(), DateTime.t() | nil) :: :ok
  def record_sync(peer_id, key_fingerprint, timestamp \\ nil) do
    GenServer.call(
      __MODULE__,
      {:record_sync, peer_id, key_fingerprint, timestamp || DateTime.utc_now()}
    )
  end

  @spec set_sync_password(String.t()) :: :ok
  def set_sync_password(password) do
    hash = :crypto.hash(:sha256, password) |> Base.encode64()
    GenServer.call(__MODULE__, {:set_sync_password, hash})
  end

  @spec verify_sync_password(String.t()) :: boolean()
  def verify_sync_password(password) do
    hash = :crypto.hash(:sha256, password) |> Base.encode64()
    GenServer.call(__MODULE__, {:verify_sync_password, hash})
  end

  @spec verify_sync_password_hash(String.t()) :: boolean()
  def verify_sync_password_hash(hash) do
    GenServer.call(__MODULE__, {:verify_sync_password, hash})
  end

  @impl true
  @spec init([]) :: {:ok, state()}
  def init([]) do
    state = load_state()
    {:ok, state}
  end

  @impl true
  def handle_call(:get_state, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:update_state, fun}, _from, state) do
    new_state = fun.(state)
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  def handle_call({:add_peer, peer}, _from, state) do
    peer_id = normalize_peer_id(peer.id)
    peer_struct = to_peer_struct(peer, peer_id)
    peers = Map.put(state.peers, peer_id, peer_struct)
    new_state = %{state | peers: peers}
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  def handle_call({:remove_peer, peer_id}, _from, state) do
    peers = Map.delete(state.peers, peer_id)
    new_state = %{state | peers: peers}
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  def handle_call(:get_peers, _from, state) do
    {:reply, Map.values(state.peers), state}
  end

  def handle_call({:record_sync, peer_id, fingerprint, timestamp}, _from, state) do
    fingerprint_syncs = Map.get(state.key_syncs, fingerprint, %{})
    fingerprint_syncs = Map.put(fingerprint_syncs, peer_id, timestamp)
    key_syncs = Map.put(state.key_syncs, fingerprint, fingerprint_syncs)
    new_state = %{state | key_syncs: key_syncs, last_sync: timestamp}
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  def handle_call({:set_sync_password, hash}, _from, state) do
    new_state = %{state | sync_password_hash: hash}
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  def handle_call({:verify_sync_password, hash}, _from, state) do
    result = state.sync_password_hash == hash
    {:reply, result, state}
  end

  @spec load_state() :: state()
  defp load_state do
    path = state_path()

    default = %State{
      device_id: Crispkey.device_id(),
      peers: %{},
      key_syncs: %{},
      last_sync: nil,
      initialized: false,
      sync_password_hash: nil
    }

    case File.read(path) do
      {:ok, data} ->
        case Jason.decode(data) do
          {:ok, raw_state} ->
            parse_state(raw_state, default)

          _ ->
            default
        end

      _ ->
        default
    end
  end

  @spec parse_state(map(), State.t()) :: State.t()
  defp parse_state(raw_state, default) do
    device_id = Map.get(raw_state, "device_id", default.device_id)
    initialized = Map.get(raw_state, "initialized", false)
    sync_password_hash = Map.get(raw_state, "sync_password_hash")
    last_sync = parse_datetime(Map.get(raw_state, "last_sync"))

    peers =
      raw_state
      |> Map.get("peers", %{})
      |> parse_peers()

    key_syncs =
      raw_state
      |> Map.get("key_syncs", %{})
      |> parse_key_syncs()

    %State{
      device_id: device_id,
      initialized: initialized,
      sync_password_hash: sync_password_hash,
      peers: peers,
      key_syncs: key_syncs,
      last_sync: last_sync
    }
  end

  @spec parse_peers(map()) :: %{String.t() => Peer.t()}
  defp parse_peers(peers_map) do
    for {id, peer_data} <- peers_map, into: %{} do
      peer_id = normalize_peer_id(id)

      peer = %Peer{
        id: peer_id,
        host: Map.get(peer_data, "host"),
        port: Map.get(peer_data, "port"),
        paired_at: parse_datetime(Map.get(peer_data, "paired_at"))
      }

      {peer_id, peer}
    end
  end

  @spec parse_key_syncs(map()) :: %{String.t() => %{String.t() => DateTime.t()}}
  defp parse_key_syncs(key_syncs_map) do
    for {fingerprint, syncs} <- key_syncs_map, into: %{} do
      parsed_syncs =
        for {peer_id, timestamp} <- syncs, into: %{} do
          {peer_id, parse_datetime(timestamp)}
        end

      {fingerprint, parsed_syncs}
    end
  end

  @spec parse_datetime(String.t() | nil) :: DateTime.t() | nil
  defp parse_datetime(nil), do: nil

  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  defp parse_datetime(_), do: nil

  @spec save_state(state()) :: :ok
  defp save_state(state) do
    path = state_path()
    File.mkdir_p!(Path.dirname(path))
    json = state_to_json(state)
    File.write!(path, json)
    :ok
  end

  @spec state_to_json(state()) :: String.t()
  defp state_to_json(state) do
    json_state = %{
      "device_id" => state.device_id,
      "initialized" => state.initialized,
      "sync_password_hash" => state.sync_password_hash,
      "peers" => peers_to_json(state.peers),
      "key_syncs" => key_syncs_to_json(state.key_syncs),
      "last_sync" => state.last_sync && DateTime.to_iso8601(state.last_sync)
    }

    Jason.encode!(json_state, pretty: true)
  end

  @spec peers_to_json(%{String.t() => Peer.t()}) :: map()
  defp peers_to_json(peers) do
    for {id, peer} <- peers, into: %{} do
      {id,
       %{
         "id" => peer.id,
         "host" => peer.host,
         "port" => peer.port,
         "paired_at" => peer.paired_at && DateTime.to_iso8601(peer.paired_at)
       }}
    end
  end

  @spec key_syncs_to_json(%{String.t() => %{String.t() => DateTime.t()}}) :: map()
  defp key_syncs_to_json(key_syncs) do
    for {fingerprint, syncs} <- key_syncs, into: %{} do
      json_syncs =
        for {peer_id, timestamp} <- syncs, into: %{} do
          {peer_id, DateTime.to_iso8601(timestamp)}
        end

      {fingerprint, json_syncs}
    end
  end

  @spec state_path() :: String.t()
  defp state_path do
    Path.join(Crispkey.data_dir(), "state.json")
  end

  @spec normalize_peer_id(String.t() | atom()) :: String.t()
  defp normalize_peer_id(id) when is_atom(id), do: Atom.to_string(id)
  defp normalize_peer_id(id) when is_binary(id), do: id

  @spec to_peer_struct(map() | Peer.t(), String.t()) :: Peer.t()
  defp to_peer_struct(%Peer{} = peer, _id), do: peer

  defp to_peer_struct(peer_map, id) do
    %Peer{
      id: id,
      host: Map.get(peer_map, :host) || Map.get(peer_map, "host"),
      port: Map.get(peer_map, :port) || Map.get(peer_map, "port"),
      paired_at: Map.get(peer_map, :paired_at) || Map.get(peer_map, "paired_at")
    }
  end
end
