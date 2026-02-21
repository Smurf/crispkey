defmodule Crispkey.Sync.Discovery do
  @moduledoc """
  UDP multicast peer discovery on local network.
  """

  @multicast_addr {224, 0, 0, 251}
  @discovery_port 4830
  @service_name "_crispkey._tcp.local"

  def discover(timeout_ms \\ 5000) do
    {:ok, socket} = :gen_udp.open(0, [
      :binary,
      {:reuseaddr, true},
      {:active, false}
    ])
    
    msg = encode_announcement()
    :gen_udp.send(socket, @multicast_addr, @discovery_port, msg)
    
    peers = collect_responses(socket, timeout_ms, %{})
    
    :gen_udp.close(socket)
    
    Map.values(peers)
  end

  defp collect_responses(socket, timeout_ms, peers) do
    start = System.monotonic_time(:millisecond)
    do_collect(socket, start, timeout_ms, peers)
  end

  defp do_collect(socket, start, timeout_ms, peers) do
    elapsed = System.monotonic_time(:millisecond) - start
    remaining = timeout_ms - elapsed
    
    if remaining <= 0 do
      peers
    else
      case :gen_udp.recv(socket, 0, min(remaining, 500)) do
        {:ok, {ip, _port, data}} ->
          case parse_announcement(data) do
            {:ok, peer} ->
              if peer.id != Crispkey.device_id() do
                peer = Map.put(peer, :ip, format_ip(ip))
                do_collect(socket, start, timeout_ms, Map.put(peers, peer.id, peer))
              else
                do_collect(socket, start, timeout_ms, peers)
              end
            :error ->
              do_collect(socket, start, timeout_ms, peers)
          end
        
        {:error, :timeout} ->
          do_collect(socket, start, timeout_ms, peers)
        
        {:error, _} ->
          peers
      end
    end
  end

  defp format_ip({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

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
      {:ok, %{id: msg.id, port: msg.port}}
    else
      _ -> :error
    end
  end
end
