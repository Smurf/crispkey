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
      ["discover" | rest] -> discover(rest)
      ["pair", host] -> pair(host)
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
      crispkey discover          Find devices on network
      crispkey pair <host>       Pair with a device
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
      IO.puts("No paired devices. Use 'crispkey discover' and 'crispkey pair <host>'")
    else
      IO.puts("Paired devices:")
      Enum.each(peers, fn peer ->
        IO.puts("  #{peer.id} - #{peer.host}:#{peer.port}")
      end)
    end
  end

  defp discover(args) do
    timeout = case args do
      [t] -> String.to_integer(t) * 1000
      _ -> 5000
    end
    
    IO.puts("Discovering devices (#{timeout}ms)...")
    
    case Crispkey.Sync.Discovery.discover(timeout) do
      [] ->
        IO.puts("No devices found")
      
      peers ->
        IO.puts("Found #{length(peers)} device(s):")
        Enum.each(peers, fn peer ->
          IO.puts("  #{peer.id} on port #{peer.port}")
        end)
    end
  end

  defp pair(host) do
    IO.puts("Pairing with #{host}...")
    
    case Crispkey.Sync.Listener.connect(host) do
      {:ok, peer} ->
        IO.puts("Connected to peer")
        Crispkey.Store.LocalState.add_peer(%{
          id: peer,
          host: host,
          port: Application.get_env(:crispkey, :sync_port, 4829),
          paired_at: DateTime.utc_now()
        })
        IO.puts("Paired successfully")
      
      {:error, reason} ->
        IO.puts("Connection failed: #{inspect(reason)}")
    end
  end

  defp sync(args) do
    state = Crispkey.Store.LocalState.get_state()
    
    peers = case args do
      [peer_id] -> [%{id: peer_id}]
      [] -> Map.values(state.peers)
    end
    
    if Enum.empty?(peers) do
      IO.puts("No devices to sync with. Use 'crispkey pair <host>' first.")
    else
      Enum.each(peers, fn peer ->
        IO.puts("Syncing with #{peer.id}...")
        
        case Crispkey.Sync.Listener.sync_with(peer.id) do
          :ok -> IO.puts("Sync complete with #{peer.id}")
          {:error, reason} -> IO.puts("Sync failed: #{inspect(reason)}")
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
