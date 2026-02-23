defmodule Crispkey.Sync.Daemon do
  @moduledoc """
  Background daemon for discovery and sync.
  """

  use GenServer

  @multicast_addr {224, 0, 0, 251}
  @discovery_port 4830
  @service_name "_crispkey._tcp.local"

  @type state :: %{
          udp_socket: :gen_udp.socket(),
          port: non_neg_integer()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec stop() :: :ok
  def stop do
    GenServer.cast(__MODULE__, :stop)
  end

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    port = Keyword.get(opts, :discovery_port, @discovery_port)

    {:ok, udp_socket} =
      :gen_udp.open(port, [
        :binary,
        {:reuseaddr, true},
        {:ip, {0, 0, 0, 0}},
        {:multicast_if, {0, 0, 0, 0}},
        {:multicast_ttl, 1},
        {:multicast_loop, true},
        {:add_membership, {@multicast_addr, {0, 0, 0, 0}}}
      ])

    {:ok, %{udp_socket: udp_socket, port: port}}
  end

  @impl true
  def handle_info({:udp, socket, sender_ip, sender_port, data}, state) do
    case parse_announcement(data) do
      {:ok, peer} ->
        if peer.id != Crispkey.device_id() do
          respond_to_discovery(socket, sender_ip, sender_port)
        end

      _ ->
        :ok
    end

    {:noreply, state}
  end

  def handle_info({:udp_closed, _socket}, state) do
    {:stop, :udp_closed, state}
  end

  @impl true
  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  @spec respond_to_discovery(:gen_udp.socket(), :inet.ip_address(), non_neg_integer()) :: :ok
  defp respond_to_discovery(socket, sender_ip, sender_port) do
    response = %{
      service: @service_name,
      id: Crispkey.device_id(),
      port: Application.get_env(:crispkey, :sync_port, 4829)
    }

    :gen_udp.send(socket, sender_ip, sender_port, Jason.encode!(response))
  end

  @spec parse_announcement(binary()) :: {:ok, %{id: String.t(), port: non_neg_integer()}} | :error
  defp parse_announcement(data) do
    with {:ok, msg} <- Jason.decode(data),
         true <- Map.get(msg, "service") == @service_name,
         id when is_binary(id) <- Map.get(msg, "id"),
         port when is_integer(port) <- Map.get(msg, "port") do
      {:ok, %{id: id, port: port}}
    else
      _ -> :error
    end
  end
end
