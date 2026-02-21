defmodule Crispkey.CLI do
  @moduledoc """
  Command-line interface for crispkey.
  """

  def main(args) do
    Application.ensure_all_started(:crispkey)
    
    case args do
      [] -> help()
      ["help" | _] -> help()
      ["init" | _] -> init()
      ["status" | _] -> status()
      ["keys" | _] -> list_keys()
      ["devices"] -> devices()
      ["daemon" | _] -> daemon()
      ["discover" | rest] -> discover(rest)
      ["pair", target] -> pair(target)
      ["sync" | rest] -> sync(rest)
      ["export", fp | _] -> export_key(fp)
      ["wrap", fp | _] -> wrap_key(fp)
      ["unwrap", file | _] -> unwrap_key(file)
      _ -> help()
    end
  end

  defp help do
    IO.puts """
    crispkey - GPG key synchronization
    
    Usage:
      crispkey init              Initialize crispkey
      crispkey status            Show sync status
      crispkey keys              List local GPG keys
      crispkey devices           List paired devices
      crispkey daemon            Start background sync daemon
      crispkey discover [sec]    Find devices on network
      crispkey pair <id|host>    Pair with a device (by ID or IP)
      crispkey sync [device]     Sync keys with device(s)
      crispkey export <fp>       Export key (armored)
      crispkey wrap <fp>         Export wrapped (encrypted) key
      crispkey unwrap <file>     Import wrapped key
    """
  end

  defp init do
    IO.puts("Initializing crispkey...")
    
    File.mkdir_p!(Crispkey.data_dir())
    
    passphrase = get_passphrase("Enter master passphrase: ")
    confirm = get_passphrase("Confirm passphrase: ")
    
    if passphrase != confirm do
      IO.puts("Passphrases do not match")
      System.halt(1)
    end
    
    test_data = "crispkey_init_test"
    wrapped = Crispkey.Crypto.KeyWrapper.wrap(test_data, passphrase)
    
    case Crispkey.Crypto.KeyWrapper.unwrap(wrapped, passphrase) do
      {:ok, ^test_data} ->
        Crispkey.Store.LocalState.update_state(fn s -> %{s | initialized: true} end)
        IO.puts("Initialized successfully. Device ID: #{Crispkey.device_id()}")
      
      {:error, _} ->
        IO.puts("Passphrase verification failed")
        System.halt(1)
    end
  end

  defp status do
    state = Crispkey.Store.LocalState.get_state()
    
    IO.puts("Device ID: #{state.device_id}")
    IO.puts("Initialized: #{state.initialized}")
    IO.puts("Paired devices: #{map_size(state.peers)}")
    IO.puts("Last sync: #{state.last_sync || "never"}")
    IO.puts("Data dir: #{Crispkey.data_dir()}")
    IO.puts("GPG home: #{Crispkey.gpg_homedir()}")
  end

  defp list_keys do
    case Crispkey.GPG.Interface.list_public_keys() do
      {:ok, pub_keys} ->
        IO.puts("\nPublic keys:")
        Enum.each(pub_keys, &print_key/1)
      
      {:error, {_, msg}} ->
        IO.puts("Error listing public keys: #{msg}")
    end
    
    case Crispkey.GPG.Interface.list_secret_keys() do
      {:ok, sec_keys} ->
        IO.puts("\nSecret keys:")
        Enum.each(sec_keys, &print_key/1)
      
      {:error, {_, msg}} ->
        IO.puts("Error listing secret keys: #{msg}")
    end
  end

  defp print_key(key) do
    IO.puts("  #{key.key_id} #{key.algorithm}/#{key.bits}")
    Enum.each(key.uids, fn uid ->
      IO.puts("    #{uid.string}")
    end)
  end

  defp devices do
    peers = Crispkey.Store.LocalState.get_peers()
    
    if Enum.empty?(peers) do
      IO.puts("No paired devices. Use 'crispkey discover' and 'crispkey pair <id|host>'")
    else
      IO.puts("Paired devices:")
      Enum.each(peers, fn peer ->
        IO.puts("  #{peer.id} - #{peer.host}:#{peer.port}")
      end)
    end
  end

  defp daemon do
    IO.puts("Starting crispkey daemon...")
    IO.puts("Device ID: #{Crispkey.device_id()}")
    IO.puts("Listening for discovery on port 4830")
    IO.puts("Listening for sync on port 4829")
    IO.puts("Press Ctrl+C to stop")
    
    {:ok, _listener} = Crispkey.Sync.Listener.start_link([])
    {:ok, _daemon} = Crispkey.Sync.Daemon.start_link([])
    
    Process.flag(:trap_exit, true)
    receive do
      {:EXIT, _, _} -> :ok
    end
  end

  defp discover(args) do
    timeout = case args do
      [t] -> String.to_integer(t) * 1000
      _ -> 5000
    end
    
    IO.puts("Discovering devices (#{div(timeout, 1000)}s)...")
    IO.puts("Make sure 'crispkey daemon' is running on other devices.")
    
    peers = Crispkey.Sync.Discovery.discover(timeout)
    
    if Enum.empty?(peers) do
      IO.puts("No devices found")
    else
      Crispkey.Store.Peers.save(peers)
      
      IO.puts("Found #{length(peers)} device(s):")
      Enum.each(peers, fn peer ->
        IO.puts("  #{peer.id} @ #{peer.ip}:#{peer.port}")
      end)
    end
  end

  defp pair(target) do
    {host, device_id} = resolve_target(target)
    
    IO.puts("Pairing with #{device_id} @ #{host}...")
    
    case Crispkey.Sync.Connection.connect(host) do
      {:ok, %{peer_id: peer_id}} ->
        Crispkey.Store.LocalState.add_peer(%{
          id: peer_id,
          host: host,
          port: Application.get_env(:crispkey, :sync_port, 4829),
          paired_at: DateTime.utc_now()
        })
        IO.puts("Paired successfully with #{peer_id}")
      
      {:error, reason} ->
        IO.puts("Connection failed: #{inspect(reason)}")
    end
  end

  defp resolve_target(target) do
    if is_ip_address?(target) do
      {target, target}
    else
      case Crispkey.Store.Peers.find(target) do
        nil ->
          if looks_like_device_id?(target) do
            IO.puts("Device #{target} not found in recent discoveries.")
            IO.puts("Run 'crispkey discover' first to find devices on your network.")
            System.halt(1)
          else
            {target, target}
          end
        
        peer ->
          {peer.ip, peer.id}
      end
    end
  end

  defp is_ip_address?(str) do
    case String.split(str, ".") do
      [a, b, c, d] ->
        Enum.all?([a, b, c, d], fn part ->
          case Integer.parse(part) do
            {n, ""} -> n >= 0 and n <= 255
            _ -> false
          end
        end)
      _ -> false
    end
  end

  defp looks_like_device_id?(str) do
    String.length(str) == 16 and String.match?(str, ~r/^[a-f0-9]+$/)
  end

  defp sync(args) do
    state = Crispkey.Store.LocalState.get_state()
    
    peers = case args do
      [peer_id] -> 
        case Map.get(state.peers, peer_id) do
          nil -> 
            IO.puts("Device #{peer_id} not paired. Use 'crispkey pair #{peer_id}' first.")
            System.halt(1)
          peer -> [peer]
        end
      [] -> Map.values(state.peers)
    end
    
    if Enum.empty?(peers) do
      IO.puts("No devices to sync with. Use 'crispkey pair <id|host>' first.")
    else
      Enum.each(peers, fn peer ->
        IO.puts("Syncing with #{peer.id}...")
        
        case Crispkey.Sync.Connection.connect(peer.host) do
          {:ok, conn} ->
            result = Crispkey.Sync.Connection.sync(conn.socket)
            Crispkey.Sync.Connection.close(conn)
            
            case result do
              :ok -> IO.puts("Sync complete with #{peer.id}")
              {:error, reason} -> IO.puts("Sync failed: #{inspect(reason)}")
            end
          
          {:error, reason} ->
            IO.puts("Connection failed: #{inspect(reason)}")
        end
      end)
    end
  end

  defp export_key(fingerprint) do
    case Crispkey.GPG.Interface.export_public_key(fingerprint) do
      {:ok, data} ->
        IO.puts(data)
      
      {:error, {_, msg}} ->
        IO.puts("Export failed: #{msg}")
    end
  end

  defp wrap_key(fingerprint) do
    passphrase = get_passphrase("Enter wrapping passphrase: ")
    
    with {:ok, pub_data} <- Crispkey.GPG.Interface.export_public_key(fingerprint),
         {:ok, sec_data} <- Crispkey.GPG.Interface.export_secret_key(fingerprint),
         {:ok, trust_data} <- Crispkey.GPG.Interface.export_trustdb() do
      
      bundle = Jason.encode!(%{
        public: pub_data,
        secret: sec_data,
        trust: trust_data,
        fingerprint: fingerprint
      })
      
      wrapped = Crispkey.Crypto.KeyWrapper.wrap(bundle, passphrase)
      
      filename = "crispkey_#{fingerprint}.wrapped"
      File.write!(filename, wrapped)
      IO.puts("Wrapped key written to #{filename}")
    else
      {:error, {_, msg}} ->
        IO.puts("Export failed: #{msg}")
    end
  end

  defp unwrap_key(file) do
    passphrase = get_passphrase("Enter wrapping passphrase: ")
    wrapped = File.read!(file)
    
    case Crispkey.Crypto.KeyWrapper.unwrap(wrapped, passphrase) do
      {:ok, bundle_json} ->
        bundle = Jason.decode!(bundle_json, keys: :atoms)
        
        with {:ok, _} <- Crispkey.GPG.Interface.import_key(bundle.public),
             {:ok, _} <- Crispkey.GPG.Interface.import_key(bundle.secret),
             {:ok, _} <- Crispkey.GPG.Interface.import_trustdb(bundle.trust) do
          IO.puts("Imported key #{bundle.fingerprint}")
        else
          {:error, {_, msg}} ->
            IO.puts("Import failed: #{msg}")
        end
      
      {:error, :decryption_failed} ->
        IO.puts("Decryption failed - wrong passphrase?")
    end
  end

  defp get_passphrase(prompt) do
    IO.write(:stderr, prompt)
    passphrase = IO.gets("") |> to_string() |> String.replace("\r", "") |> String.trim()
    
    if String.length(passphrase) < 8 do
      IO.puts("\nPassphrase must be at least 8 characters")
      System.halt(1)
    end
    
    passphrase
  end
end
