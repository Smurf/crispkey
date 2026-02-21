defmodule Crispkey.Store.LocalState do
  use GenServer

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def get_state do
    GenServer.call(__MODULE__, :get_state)
  end

  def update_state(fun) do
    GenServer.call(__MODULE__, {:update_state, fun})
  end

  def add_peer(peer) do
    GenServer.call(__MODULE__, {:add_peer, peer})
  end

  def remove_peer(peer_id) do
    GenServer.call(__MODULE__, {:remove_peer, peer_id})
  end

  def get_peers do
    GenServer.call(__MODULE__, :get_peers)
  end

  def record_sync(peer_id, key_fingerprint, timestamp \\ nil) do
    GenServer.call(__MODULE__, {:record_sync, peer_id, key_fingerprint, timestamp || DateTime.utc_now()})
  end

  @impl true
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
    peer_id = if is_atom(peer.id), do: Atom.to_string(peer.id), else: peer.id
    peer = Map.put(peer, :id, peer_id)
    peers = Map.put(state.peers, peer_id, peer)
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
    key_syncs = Map.get(state.key_syncs, fingerprint, %{})
    key_syncs = Map.put(key_syncs, peer_id, timestamp)
    key_syncs = Map.put(state.key_syncs, fingerprint, key_syncs)
    new_state = %{state | key_syncs: key_syncs, last_sync: timestamp}
    save_state(new_state)
    {:reply, :ok, new_state}
  end

  defp load_state do
    path = state_path()
    
    default = %{
      device_id: Crispkey.device_id(),
      peers: %{},
      key_syncs: %{},
      last_sync: nil,
      initialized: false
    }
    
    case File.read(path) do
      {:ok, data} ->
        case Jason.decode(data, keys: :atoms) do
          {:ok, state} -> 
            peers = Map.get(state, :peers, %{})
            peers = for {k, v} <- peers, into: %{} do
              key = if is_atom(k), do: Atom.to_string(k), else: k
              {key, v}
            end
            state = Map.put(state, :peers, peers)
            Map.merge(default, state)
          _ -> default
        end
      _ -> default
    end
  end

  defp save_state(state) do
    path = state_path()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, Jason.encode!(state, pretty: true))
  end

  defp state_path do
    Path.join(Crispkey.data_dir(), "state.json")
  end
end
