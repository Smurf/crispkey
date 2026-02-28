defmodule Crispkey.CLI do
  @moduledoc """
  Command-line interface for crispkey.
  """

  alias Crispkey.{Crypto, Store}
  alias Crispkey.GPG.Interface, as: GPGInterface
  alias Crispkey.Store.{LocalState, Peers}
  alias Crispkey.Sync.{Connection, Daemon, Discovery, Listener}
  alias Crispkey.Vault.Manager

  @spec main([String.t()]) :: no_return()
  def main(args) do
    configure_runtime()
    {:ok, _} = Application.ensure_all_started(:crispkey)

    case args do
      ["help" | _] -> help()
      [] -> help()
      ["init" | _] -> init()
      ["unlock" | _] -> unlock()
      ["lock" | _] -> lock()
      ["status" | _] -> status()
      ["keys" | _] -> list_keys()
      ["devices"] -> devices()
      ["daemon" | _] -> daemon()
      ["discover" | rest] -> discover(rest)
      ["pair", target] -> pair(target)
      ["sync" | rest] -> sync(rest)
      ["vault" | rest] -> vault_cmd(rest)
      ["export", fp | _] -> export_key(fp)
      ["wrap", fp | _] -> wrap_key(fp)
      ["unwrap", file | _] -> unwrap_key(file)
      _ -> help()
    end
  end

  @spec help() :: no_return()
  defp help do
    IO.puts("""
    crispkey - GPG key synchronization with encrypted vaults

    Vault Commands:
      crispkey init              Initialize vault system
      crispkey unlock            Unlock vaults with master password
      crispkey lock              Lock vaults (clear master key from memory)
      crispkey vault list        List vaults
      crispkey vault import <fp> Import GPG key to vault
      crispkey vault export <fp> Export vault to GPG keyring
      crispkey vault delete <fp> Delete a vault

    Sync Commands:
      crispkey status            Show sync status
      crispkey keys              List GPG keys in keyring
      crispkey devices           List paired devices
      crispkey daemon            Start background sync daemon
      crispkey discover [sec]    Find devices on network
      crispkey pair <id|host>    Pair with a device
      crispkey sync [device]     Sync vaults with device(s)

    Legacy Commands:
      crispkey export <fp>       Export key (armored)
      crispkey wrap <fp>         Export wrapped key
      crispkey unwrap <file>     Import wrapped key
    """)

    System.halt(0)
  end

  @spec init() :: no_return()
  defp init do
    IO.puts("Initializing crispkey vault system...")

    File.mkdir_p!(Crispkey.data_dir())
    File.mkdir_p!(Manager.vaults_dir())

    passphrase = get_passphrase("Enter master password (unlocks vaults): ")
    confirm = get_passphrase("Confirm master password: ")

    if passphrase != confirm do
      IO.puts("Passwords do not match")
      System.halt(1)
    end

    sync_password = get_passphrase("Enter sync password (for remote devices): ")
    sync_confirm = get_passphrase("Confirm sync password: ")

    if sync_password != sync_confirm do
      IO.puts("Sync passwords do not match")
      System.halt(1)
    end

    :ok = Manager.initialize(passphrase)

    Store.LocalState.update_state(fn s -> %{s | initialized: true} end)
    Store.LocalState.set_sync_password(sync_password)

    IO.puts("Initialized successfully.")
    IO.puts("Device ID: #{Crispkey.device_id()}")
    IO.puts("")
    IO.puts("Vaults are encrypted and stored in: #{Manager.vaults_dir()}")
    IO.puts("Use 'crispkey vault import <fingerprint>' to import GPG keys to vaults.")

    System.halt(0)
  end

  @spec unlock() :: no_return()
  defp unlock do
    if Manager.unlocked?() do
      IO.puts("Vaults already unlocked")
      System.halt(0)
    end

    password = get_passphrase("Enter master password: ")

    case Manager.unlock(password) do
      :ok ->
        IO.puts("Vaults unlocked")
        System.halt(0)

      {:error, :invalid_password} ->
        IO.puts("Invalid password")
        System.halt(1)
    end
  end

  @spec lock() :: no_return()
  defp lock do
    Manager.lock()
    IO.puts("Vaults locked")
    System.halt(0)
  end

  @spec status() :: no_return()
  defp status do
    state = Store.LocalState.get_state()
    vault_unlocked = Manager.unlocked?()

    IO.puts("Device ID: #{state.device_id}")
    IO.puts("Initialized: #{state.initialized}")
    IO.puts("Vaults unlocked: #{vault_unlocked}")
    IO.puts("Paired devices: #{map_size(state.peers)}")
    IO.puts("Last sync: #{state.last_sync || "never"}")
    IO.puts("Data dir: #{Crispkey.data_dir()}")
    IO.puts("GPG home: #{Crispkey.gpg_homedir()}")

    if vault_unlocked do
      case Manager.list_vaults() do
        {:ok, vaults} ->
          IO.puts("Vaults: #{length(vaults)}")

        _ ->
          :ok
      end
    end

    System.halt(0)
  end

  @spec vault_cmd([String.t()]) :: no_return()
  defp vault_cmd(["list" | _]) do
    ensure_unlocked!()

    case Manager.list_vaults() do
      {:ok, []} ->
        IO.puts("No vaults. Use 'crispkey vault import <fingerprint>' to add one.")

      {:ok, vaults} ->
        IO.puts("Vaults:")
        Enum.each(vaults, &print_vault_entry/1)
    end

    System.halt(0)
  end

  defp vault_cmd(["import", fingerprint | _]) do
    ensure_unlocked!()

    with {:ok, pub_data} <- GPGInterface.export_public_key(fingerprint),
         {:ok, sec_data} <- GPGInterface.export_secret_key(fingerprint),
         {:ok, trust_data} <- GPGInterface.export_trustdb() do
      :ok = Manager.create_vault(fingerprint, pub_data, sec_data, trust_data)
      IO.puts("Imported key #{fingerprint} to vault")
    else
      {:error, {2, _}} ->
        case GPGInterface.export_public_key(fingerprint) do
          {:ok, pub_data} ->
            {:ok, trust_data} = GPGInterface.export_trustdb()
            :ok = Manager.create_vault(fingerprint, pub_data, nil, trust_data)
            IO.puts("Imported public key #{fingerprint} to vault (no secret key)")

          {:error, reason} ->
            IO.puts("Export failed: #{inspect(reason)}")
            System.halt(1)
        end

      {:error, reason} ->
        IO.puts("Export failed: #{inspect(reason)}")
        System.halt(1)
    end

    System.halt(0)
  end

  defp vault_cmd(["export", fingerprint | _]) do
    ensure_unlocked!()

    case Manager.read_vault(fingerprint) do
      {:ok, vault} ->
        results = []

        results =
          if vault.public_key do
            case GPGInterface.import_key(vault.public_key) do
              {:ok, _} -> [{:public, :ok} | results]
              {:error, reason} -> [{:public, {:error, reason}} | results]
            end
          else
            results
          end

        results =
          if vault.secret_key do
            case GPGInterface.import_key(vault.secret_key) do
              {:ok, _} -> [{:secret, :ok} | results]
              {:error, reason} -> [{:secret, {:error, reason}} | results]
            end
          else
            results
          end

        results =
          if vault.trust do
            case GPGInterface.import_trustdb(vault.trust) do
              {:ok, _} -> [{:trust, :ok} | results]
              {:error, reason} -> [{:trust, {:error, reason}} | results]
            end
          else
            results
          end

        Enum.each(results, fn
          {:public, :ok} -> IO.puts("Imported public key to GPG keyring")
          {:secret, :ok} -> IO.puts("Imported secret key to GPG keyring")
          {:trust, :ok} -> IO.puts("Imported trust database")
          {type, {:error, reason}} -> IO.puts("#{type} import failed: #{inspect(reason)}")
        end)

      {:error, :not_found} ->
        IO.puts("Vault not found: #{fingerprint}")
        System.halt(1)
    end

    System.halt(0)
  end

  defp vault_cmd(["delete", fingerprint | _]) do
    ensure_unlocked!()

    case Manager.delete_vault(fingerprint) do
      :ok ->
        IO.puts("Deleted vault: #{fingerprint}")

      {:error, :not_found} ->
        IO.puts("Vault not found: #{fingerprint}")
        System.halt(1)
    end

    System.halt(0)
  end

  defp vault_cmd(_) do
    IO.puts("""
    Usage:
      crispkey vault list
      crispkey vault import <fingerprint>
      crispkey vault export <fingerprint>
      crispkey vault delete <fingerprint>
    """)

    System.halt(1)
  end

  defp print_vault_entry(entry) do
    secret_status = if entry.has_secret, do: "[secret]", else: "[public only]"
    IO.puts("  #{entry.fingerprint} #{secret_status}")
    IO.puts("    Size: #{entry.size} bytes, Modified: #{entry.modified}")
  end

  @spec ensure_unlocked!() :: :ok
  defp ensure_unlocked! do
    unless Manager.unlocked?() do
      if master_password = System.get_env("CRISPKEY_MASTER_PASSWORD") do
        case Manager.unlock(master_password) do
          :ok ->
            :ok

          {:error, :invalid_password} ->
            IO.puts("Invalid password from CRISPKEY_MASTER_PASSWORD")
            System.halt(1)
        end
      else
        IO.puts("Vaults are locked. Run 'crispkey unlock' first.")
        System.halt(1)
      end
    end

    :ok
  end

  @spec list_keys() :: no_return()
  defp list_keys do
    case GPGInterface.list_public_keys() do
      {:ok, pub_keys} ->
        IO.puts("\nPublic keys in GPG keyring:")
        Enum.each(pub_keys, &print_key/1)

      {:error, {_, msg}} ->
        IO.puts("Error listing public keys: #{msg}")
    end

    case GPGInterface.list_secret_keys() do
      {:ok, sec_keys} ->
        IO.puts("\nSecret keys in GPG keyring:")
        Enum.each(sec_keys, &print_key/1)

      {:error, {_, msg}} ->
        IO.puts("Error listing secret keys: #{msg}")
    end

    System.halt(0)
  end

  @spec print_key(Crispkey.GPG.Key.t()) :: :ok
  defp print_key(key) do
    IO.puts("  #{key.key_id} #{key.algorithm}/#{key.bits}")

    Enum.each(key.uids, fn uid ->
      IO.puts("    #{uid.string}")
    end)

    :ok
  end

  @spec devices() :: no_return()
  defp devices do
    peers = LocalState.get_peers()

    if Enum.empty?(peers) do
      IO.puts("No paired devices. Use 'crispkey discover' and 'crispkey pair <id|host>'")
    else
      IO.puts("Paired devices:")

      Enum.each(peers, fn peer ->
        IO.puts("  #{peer.id} - #{peer.host}:#{peer.port}")
      end)
    end

    System.halt(0)
  end

  @spec daemon() :: no_return()
  defp daemon do
    IO.puts("Starting crispkey daemon...")
    IO.puts("Device ID: #{Crispkey.device_id()}")
    IO.puts("Listening for discovery on port 4830")
    IO.puts("Listening for sync on port 4829")
    IO.puts("Press Ctrl+C to stop")

    {:ok, _listener} = Listener.start_link([])
    {:ok, _daemon} = Daemon.start_link([])

    Process.flag(:trap_exit, true)

    receive do
      {:EXIT, _, _} -> :ok
    end

    System.halt(0)
  end

  @spec discover([String.t()]) :: no_return()
  defp discover(args) do
    timeout =
      case args do
        [t] -> String.to_integer(t) * 1000
        _ -> 5000
      end

    IO.puts("Discovering devices (#{div(timeout, 1000)}s)...")
    IO.puts("Make sure 'crispkey daemon' is running on other devices.")

    peers = Discovery.discover(timeout)

    if Enum.empty?(peers) do
      IO.puts("No devices found")
    else
      Peers.save(peers)

      IO.puts("Found #{length(peers)} device(s):")

      Enum.each(peers, fn peer ->
        IO.puts("  #{peer.id} @ #{peer.ip}:#{peer.port}")
      end)
    end

    System.halt(0)
  end

  @spec pair(String.t()) :: no_return()
  defp pair(target) do
    {host, device_id} = resolve_target(target)

    IO.puts("Pairing with #{device_id} @ #{host}...")

    case Connection.connect(host) do
      {:ok, %{peer_id: peer_id}} ->
        LocalState.add_peer(%{
          id: peer_id,
          host: host,
          port: Application.get_env(:crispkey, :sync_port, 4829),
          paired_at: DateTime.utc_now()
        })

        IO.puts("Paired successfully with #{peer_id}")

      {:error, reason} ->
        IO.puts("Connection failed: #{inspect(reason)}")
    end

    System.halt(0)
  end

  @spec resolve_target(String.t()) :: {String.t(), String.t()}
  defp resolve_target(target) do
    cond do
      ip_address?(target) ->
        {target, target}

      peer = Peers.find(target) ->
        {peer.ip, peer.id}

      looks_like_device_id?(target) ->
        IO.puts("Device #{target} not found in recent discoveries.")
        IO.puts("Run 'crispkey discover' first to find devices on your network.")
        System.halt(1)

      true ->
        {target, target}
    end
  end

  @spec ip_address?(String.t()) :: boolean()
  defp ip_address?(str) do
    parts = String.split(str, ".")

    if length(parts) == 4 do
      parts
      |> Enum.map(&parse_octet/1)
      |> Enum.all?(&(&1 !== nil))
    else
      false
    end
  end

  defp parse_octet(part) do
    case Integer.parse(part) do
      {n, ""} when n >= 0 and n <= 255 -> n
      _ -> nil
    end
  end

  @spec looks_like_device_id?(String.t()) :: boolean()
  defp looks_like_device_id?(str) do
    String.length(str) == 16 and String.match?(str, ~r/^[a-f0-9]+$/)
  end

  @spec sync([String.t()]) :: no_return()
  defp sync(args) do
    ensure_unlocked!()

    state = LocalState.get_state()

    peers =
      case args do
        [peer_id] ->
          case Map.get(state.peers, peer_id) do
            nil ->
              IO.puts("Device #{peer_id} not paired. Use 'crispkey pair #{peer_id}' first.")
              System.halt(1)

            peer ->
              [peer]
          end

        [] ->
          Map.values(state.peers)
      end

    if Enum.empty?(peers) do
      IO.puts("No devices to sync with. Use 'crispkey pair <id|host>' first.")
    else
      remote_password = get_passphrase("Enter remote device's sync password: ")
      Enum.each(peers, &sync_with_peer(&1, remote_password))
    end

    System.halt(0)
  end

  defp sync_with_peer(peer, remote_password) do
    IO.puts("Syncing with #{peer.id}...")

    case Connection.connect(peer.host) do
      {:ok, conn} ->
        result = Connection.sync(conn, remote_password)
        Connection.close(conn)
        report_sync_result(peer.id, result)

      {:error, reason} ->
        IO.puts("Connection failed: #{inspect(reason)}")
    end
  end

  @doc false
  defp report_sync_result(peer_id, :ok) do
    IO.puts("Sync complete with #{peer_id}")
  end

  defp report_sync_result(_peer_id, {:error, :auth_failed}) do
    IO.puts("Sync failed: Wrong sync password")
  end

  defp report_sync_result(_peer_id, {:error, reason}) do
    IO.puts("Sync failed: #{inspect(reason)}")
  end

  @spec export_key(String.t()) :: no_return()
  defp export_key(fingerprint) do
    case GPGInterface.export_public_key(fingerprint) do
      {:ok, data} ->
        IO.puts(data)

      {:error, {_, msg}} ->
        IO.puts("Export failed: #{msg}")
    end

    System.halt(0)
  end

  @spec wrap_key(String.t()) :: no_return()
  defp wrap_key(fingerprint) do
    passphrase = get_passphrase("Enter wrapping passphrase: ")

    with {:ok, pub_data} <- GPGInterface.export_public_key(fingerprint),
         {:ok, sec_data} <- GPGInterface.export_secret_key(fingerprint),
         {:ok, trust_data} <- GPGInterface.export_trustdb() do
      bundle =
        Jason.encode!(%{
          public: pub_data,
          secret: sec_data,
          trust: trust_data,
          fingerprint: fingerprint
        })

      wrapped = Crypto.KeyWrapper.wrap(bundle, passphrase)

      filename = "crispkey_#{fingerprint}.wrapped"
      File.write!(filename, wrapped)
      IO.puts("Wrapped key written to #{filename}")
    else
      {:error, {_, msg}} ->
        IO.puts("Export failed: #{msg}")
    end

    System.halt(0)
  end

  @spec unwrap_key(String.t()) :: no_return()
  defp unwrap_key(file) do
    passphrase = get_passphrase("Enter wrapping passphrase: ")
    wrapped = File.read!(file)

    case Crypto.KeyWrapper.unwrap(wrapped, passphrase) do
      {:ok, bundle_json} ->
        unwrap_key_from_bundle(bundle_json)

      {:error, :decryption_failed} ->
        IO.puts("Decryption failed - wrong passphrase?")
    end

    System.halt(0)
  end

  defp unwrap_key_from_bundle(bundle_json) do
    case Jason.decode(bundle_json) do
      {:ok, bundle} ->
        public = Map.get(bundle, "public")
        secret = Map.get(bundle, "secret")
        trust = Map.get(bundle, "trust")
        fingerprint = Map.get(bundle, "fingerprint")

        import_keys_from_bundle(public, secret, trust, fingerprint)

      {:error, _} ->
        IO.puts("Failed to parse key bundle")
    end
  end

  defp import_keys_from_bundle(public, secret, trust, fingerprint) do
    with {:ok, _} <- GPGInterface.import_key(public),
         {:ok, _} <- GPGInterface.import_key(secret),
         {:ok, _} <- GPGInterface.import_trustdb(trust) do
      IO.puts("Imported key #{fingerprint}")
    else
      {:error, {_, msg}} ->
        IO.puts("Import failed: #{msg}")
    end
  end

  @spec get_passphrase(String.t()) :: String.t()
  defp get_passphrase(prompt) do
    IO.write(:stderr, prompt)
    passphrase = IO.gets("") |> to_string() |> String.replace("\r", "") |> String.trim()

    if String.length(passphrase) < 8 do
      IO.puts("\nPassphrase must be at least 8 characters")
      System.halt(1)
    end

    passphrase
  end

  @spec configure_runtime() :: :ok
  defp configure_runtime do
    if data_dir = System.get_env("CRISPKEY_DATA_DIR") do
      Application.put_env(:crispkey, :data_dir, data_dir, persistent: true)
    end

    if gpg_home = System.get_env("GNUPGHOME") do
      Application.put_env(:crispkey, :gpg_homedir, gpg_home, persistent: true)
    end

    :ok
  end
end
