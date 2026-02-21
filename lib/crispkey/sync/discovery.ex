defmodule Crispkey.Sync.Discovery do
  @moduledoc """
  mDNS-based peer discovery on local network.
  """

  use GenServer

  @multicast_addr {224, 0, 0, 251}
  @discovery_port 4830
  @service_name "_crispkey._tcp.local"

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def discover(timeout \\ 5000) do
    GenServer.call(__MODULE__, {:discover, timeout}, timeout + 1000)
  end

  def broadcast do
    GenServer.cast(__MODULE__, :broadcast)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, @discovery_port)
    
    {:ok, socket} = :gen_udp.open(port, [
      :binary,
      {:reuseaddr, true},
      {:ip, {0, 0, 0, 0}},
      {:multicast_if, {0, 0, 0, 0}},
      {:multicast_ttl, 1},
      {:multicast_loop, true},
      {:add_membership, {@multicast_addr, {0, 0, 0, 0}}}
    ])
    
    state = %{
      socket: socket,
      port: port,
      discovered: %{}
    }
    
    {:ok, state}
  end

  @impl true
  def handle_call({:discover, timeout}, _from, state) do
    broadcast_presence(state)
    
    timer = Process.send_after(self(), :discover_timeout, timeout)
    
    {:noreply, %{state | discovering: true, discover_timer: timer}}
  end

  @impl true
  def handle_cast(:broadcast, state) do
    broadcast_presence(state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, _ip, _port, data}, state) do
    case parse_announcement(data) do
      {:ok, peer} ->
        discovered = Map.put(state.discovered, peer.id, peer)
        
        if state.discovering do
          send(self(), :collect_peer)
        end
        
        {:noreply, %{state | discovered: discovered}}
      
      _ ->
        {:noreply, state}
    end
  end

  def handle_info(:discover_timeout, state) do
    {:stop, {:shutdown, Map.values(state.discovered)}, state}
  end

  def handle_info(:collect_peer, state) do
    {:noreply, state}
  end

  defp broadcast_presence(state) do
    msg = encode_announcement()
    :gen_udp.send(state.socket, @multicast_addr, state.port, msg)
  end

  defp encode_announcement do
    %{
      service: @service_name,
      id: Crispkey.device_id(),
      port: Application.get_env(:crispkey, :sync_port, 4829)
    }
    |> Jason.encode!()
  end

  defp parse_announcement(data) do
    with {:ok, msg} <- Jason.decode(data, keys: :atoms),
         true <- msg.service == @service_name do
      {:ok, %{
        id: msg.id,
        port: msg.port
      }}
    else
      _ -> :error
    end
  end
end
