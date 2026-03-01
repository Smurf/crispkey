defmodule Crispkey.Sync.Listener do
  @moduledoc """
  TCP listener for incoming sync connections.
  """

  use GenServer

  alias Crispkey.Sync.Peer

  require Logger

  @type state :: %{
          listen_socket: :gen_tcp.socket(),
          accept_ref: reference() | nil,
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

    state = %{listen_socket: listen_socket, accept_ref: nil, connections: %{}, port: port}
    {:ok, schedule_accept(state)}
  end

  @impl true
  def handle_info(
        {:inet_async, listen_socket, ref, result},
        %{listen_socket: listen_socket, accept_ref: ref} = state
      ) do
    case result do
      {:ok, socket} ->
        case setup_connection(socket) do
          :ok -> :ok
          {:error, reason} -> Logger.error("Failed to setup connection: #{inspect(reason)}")
        end

      {:error, reason} ->
        Logger.warning("Accept failed: #{inspect(reason)}")
    end

    {:noreply, schedule_accept(%{state | accept_ref: nil})}
  end

  def handle_info({:inet_async, _listen_socket, _ref, _result}, state) do
    {:noreply, state}
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
            case :gen_tcp.controlling_process(socket, peer_pid) do
              :ok -> :ok
              {:error, reason} -> Logger.error("Failed to assign control: #{inspect(reason)}")
            end

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

  @impl true
  def terminate(reason, %{listen_socket: listen_socket}) do
    Logger.info("Listener terminating: #{inspect(reason)}")
    :gen_tcp.close(listen_socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  @spec schedule_accept(state()) :: state()
  defp schedule_accept(%{listen_socket: listen_socket} = state) do
    {:ok, ref} = :prim_inet.async_accept(listen_socket, -1)
    %{state | accept_ref: ref}
  end

  @spec setup_accept_opts(:gen_tcp.socket()) :: :ok | {:error, term()}
  defp setup_accept_opts(socket) do
    case :inet.setopts(socket, [{:active, false}, {:packet, 0}, :binary]) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @spec setup_connection(:gen_tcp.socket()) :: :ok | {:error, term()}
  defp setup_connection(socket) do
    with :ok <- setup_accept_opts(socket),
         {:ok, peer_pid} <- Peer.start(socket),
         :ok <- :gen_tcp.controlling_process(socket, peer_pid) do
      :ok
    else
      {:error, reason} ->
        :gen_tcp.close(socket)
        {:error, reason}
    end
  end
end
