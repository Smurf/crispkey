defmodule Crispkey.Sync.Discovery do
  @moduledoc """
  UDP multicast peer discovery on local network.
  """

  @multicast_addr {224, 0, 0, 251}
  @discovery_port 4830
  @service_name "_crispkey._tcp.local"

  require Logger

  @type discovered_peer :: %{
          id: String.t(),
          port: non_neg_integer(),
          ip: String.t()
        }

  @type partial_peer :: %{
          id: String.t(),
          port: non_neg_integer()
        }

  @spec discover(non_neg_integer()) :: [discovered_peer()]
  def discover(timeout_ms \\ 5000) do
    {:ok, socket} =
      :gen_udp.open(0, [
        :binary,
        {:reuseaddr, true},
        {:active, false}
      ])

    msg = encode_announcement()

    case :gen_udp.send(socket, @multicast_addr, @discovery_port, msg) do
      :ok -> :ok
      {:error, reason} -> Logger.error("Failed to send discovery: #{inspect(reason)}")
    end

    peers = collect_responses(socket, timeout_ms, %{})

    :gen_udp.close(socket)

    Map.values(peers)
  end

  @spec collect_responses(:gen_udp.socket(), non_neg_integer(), map()) :: map()
  defp collect_responses(socket, timeout_ms, peers) do
    start = System.monotonic_time(:millisecond)
    do_collect(socket, start, timeout_ms, peers)
  end

  @spec do_collect(:gen_udp.socket(), integer(), non_neg_integer(), map()) :: map()
  defp do_collect(socket, start, timeout_ms, peers) do
    elapsed = System.monotonic_time(:millisecond) - start
    remaining = timeout_ms - elapsed

    if remaining <= 0 do
      peers
    else
      collect_next_peer(socket, start, timeout_ms, remaining, peers)
    end
  end

  defp collect_next_peer(socket, start, timeout_ms, remaining, peers) do
    case :gen_udp.recv(socket, 0, min(remaining, 500)) do
      {:ok, {ip, _port, data}} ->
        handle_peer_data(socket, start, timeout_ms, peers, ip, data)

      {:error, :timeout} ->
        do_collect(socket, start, timeout_ms, peers)

      {:error, _} ->
        peers
    end
  end

  defp handle_peer_data(socket, start, timeout_ms, peers, ip, data) do
    case parse_announcement(data) do
      {:ok, peer} ->
        if peer.id != Crispkey.device_id() do
          peer = Map.put(peer, :ip, format_ip(ip))
          do_collect(socket, start, timeout_ms, Map.put(peers, peer.id, peer))
        else
          do_collect(socket, start, timeout_ms, peers)
        end

      _ ->
        do_collect(socket, start, timeout_ms, peers)
    end
  end

  @spec format_ip(:inet.ip_address()) :: String.t()
  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  @spec encode_announcement() :: binary()
  defp encode_announcement do
    %{
      service: @service_name,
      id: Crispkey.device_id(),
      port: Application.get_env(:crispkey, :sync_port, 4829)
    }
    |> Jason.encode!()
  end

  @spec parse_announcement(binary()) :: {:ok, partial_peer()} | :error
  defp parse_announcement(data) do
    case Jason.decode(data) do
      {:ok, msg} ->
        if Map.get(msg, "service") == @service_name do
          id = Map.get(msg, "id")
          port = Map.get(msg, "port")

          if is_binary(id) and is_integer(port) do
            {:ok, %{id: id, port: port}}
          else
            :error
          end
        else
          :error
        end

      {:error, _} ->
        :error
    end
  end
end
