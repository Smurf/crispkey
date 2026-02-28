defmodule Crispkey.Sync.Listener do
  @moduledoc """
  TCP listener for incoming sync connections.
  """

  use GenServer

  alias Crispkey.Sync.Peer

  @type state :: %{
          listen_socket: :gen_tcp.socket(),
          connections: %{String.t() => pid()},
          port: non_neg_integer()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @spec connect(String.t(), non_neg_integer() | nil) :: {:ok, pid()} | {:error, term()}
  def connect(host, port \\ nil) do
    GenServer.call(
      __MODULE__,
      {:connect, host, port || Application.get_env(:crispkey, :sync_port, 4829)}
    )
  end

  @spec sync_with(String.t()) :: :ok | {:error, term()}
  def sync_with(peer_id) do
    GenServer.call(__MODULE__, {:sync_with, peer_id}, 60_000)
  end

  @impl true
  @spec init([]) :: {:ok, state()}
  def init([]) do
    port = Application.get_env(:crispkey, :sync_port, 4829)

    {:ok, listen_socket} =
      :gen_tcp.listen(port, [
        :binary,
        {:active, false},
        {:reuseaddr, true}
      ])

    send(self(), :accept)

    {:ok, %{listen_socket: listen_socket, connections: %{}, port: port}}
  end

  @impl true
  def handle_info(:accept, state) do
    case :gen_tcp.accept(state.listen_socket, 0) do
      {:ok, socket} ->
        case Peer.start(socket) do
          {:ok, peer_pid} ->
            :gen_tcp.controlling_process(socket, peer_pid)

          _ ->
            :ok
        end

        send(self(), :accept)
        {:noreply, state}

      {:error, :timeout} ->
        send(self(), :accept)
        {:noreply, state}
    end
  end

  def handle_info({:tcp, _socket, _data}, state) do
    {:noreply, state}
  end

  def handle_info({:tcp_closed, _socket}, state) do
    {:noreply, state}
  end

  def handle_info({:tcp_error, _socket, _reason}, state) do
    {:noreply, state}
  end

  @impl true
  def handle_call({:connect, host, port}, _from, state) do
    case :gen_tcp.connect(String.to_charlist(host), port, [:binary, {:active, false}], 5000) do
      {:ok, socket} ->
        case Peer.start(socket, is_client: true) do
          {:ok, peer_pid} ->
            :gen_tcp.controlling_process(socket, peer_pid)
            {:reply, {:ok, peer_pid}, state}

          {:error, reason} ->
            :gen_tcp.close(socket)
            {:reply, {:error, reason}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:sync_with, peer_id}, _from, state) do
    result = Peer.sync(peer_id)
    {:reply, result, state}
  end
end
