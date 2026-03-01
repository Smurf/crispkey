defmodule Crispkey.CLI do
  @moduledoc """
  Command-line interface for crispkey.
  """

  alias Crispkey.Store
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
      ["yubikey" | rest] -> yubikey_cmd(rest)
      _ -> help()
    end
  end

  @spec help() :: no_return()
  defp help do
    IO.puts("""
    crispkey - GPG key synchronization with encrypted vaults

    Vault Commands:
      crispkey init              Initialize vault system
      crispkey unlock            Unlock vaults with master password or YubiKey
      crispkey lock              Lock vaults (clear master key from memory)
      crispkey vault list        List vaults
      crispkey vault import <fp> Import GPG key to vault
      crispkey vault export <fp> Export vault to GPG keyring
      crispkey vault delete <fp> Delete a vault

    YubiKey Commands:
      crispkey yubikey enroll      Enroll a new YubiKey/FIDO2 device
      crispkey yubikey unlock      Unlock vaults with enrolled YubiKey
      crispkey yubikey list        List enrolled YubiKey credentials
      crispkey yubikey remove <id> Remove enrolled credential
      crispkey yubikey status      Show YubiKey availability

    Sync Commands:
      crispkey status            Show sync status
      crispkey keys              List GPG keys in keyring
      crispkey devices           List paired devices
      crispkey daemon            Start background sync daemon
      crispkey discover [sec]    Find devices on network
      crispkey pair <id|host>    Pair with a device
      crispkey sync [device]     Sync vaults with device(s)
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

    if Manager.yubikey_enrolled?() do
      IO.puts("YubiKey available. Press Enter to use YubiKey, or enter password.")
      password = IO.gets("Password or Enter for YubiKey: ") |> String.trim()

      if password == "" do
        case Manager.unlock_with_yubikey() do
          :ok ->
            IO.puts("Vaults unlocked with YubiKey")
            System.halt(0)

          {:error, reason} ->
            IO.puts("YubiKey unlock failed: #{inspect(reason)}")
            IO.puts("Trying password...")
        end
      else
        unlock_with_password(password)
      end
    else
      password = get_passphrase("Enter master password: ")
      unlock_with_password(password)
    end
  end

  defp unlock_with_password(password) do
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

  @spec yubikey_cmd([String.t()]) :: no_return()
  defp yubikey_cmd(args) do
    case args do
      [] ->
        yubikey_status()

      ["enroll" | _] ->
        yubikey_enroll()

      ["unlock" | _] ->
        yubikey_unlock()

      ["list" | _] ->
        yubikey_list()

      ["remove", cred_id] ->
        yubikey_remove(cred_id)

      ["status" | _] ->
        yubikey_status()

      _ ->
        IO.puts("Usage:")
        IO.puts("  crispkey yubikey enroll      - Enroll a new YubiKey")
        IO.puts("  crispkey yubikey unlock      - Unlock with YubiKey")
        IO.puts("  crispkey yubikey list       - List enrolled credentials")
        IO.puts("  crispkey yubikey remove <id> - Remove credential")
        IO.puts("  crispkey yubikey status     - Show YubiKey status")
        System.halt(1)
    end
  end

  @spec yubikey_enroll() :: no_return()
  defp yubikey_enroll do
    unless Manager.unlocked?() do
      IO.puts("Error: Vaults must be unlocked first. Run 'crispkey unlock'.")
      System.halt(1)
    end

    unless Manager.yubikey_available?() do
      IO.puts("Error: No YubiKey or FIDO2 device detected.")
      IO.puts("Please insert a YubiKey and try again.")
      System.halt(1)
    end

    if Manager.yubikey_enrolled?() do
      IO.puts("Warning: A YubiKey is already enrolled. Enrolling another will replace it.")
    end

    IO.puts("Enrolling YubiKey...")
    IO.puts("Please touch your YubiKey when it blinks.")

    case Manager.enroll_yubikey("") do
      :ok ->
        IO.puts("YubiKey enrolled successfully!")
        IO.puts("You can now unlock your vaults with 'crispkey yubikey unlock'")
        System.halt(0)

      {:error, :not_available} ->
        IO.puts("Error: FIDO2 tools not available. Please install libfido2.")
        System.halt(1)

      {:error, reason} ->
        IO.puts("Error enrolling YubiKey: #{inspect(reason)}")
        System.halt(1)
    end
  end

  @spec yubikey_unlock() :: no_return()
  defp yubikey_unlock do
    if Manager.unlocked?() do
      IO.puts("Vaults already unlocked")
      System.halt(0)
    end

    unless Manager.yubikey_enrolled?() do
      IO.puts("Error: No YubiKey enrolled. Run 'crispkey yubikey enroll' first.")
      System.halt(1)
    end

    IO.puts("Touch your YubiKey to unlock vaults...")

    case Manager.unlock_with_yubikey() do
      :ok ->
        IO.puts("Vaults unlocked with YubiKey")
        System.halt(0)

      {:error, :not_enrolled} ->
        IO.puts("Error: No YubiKey enrolled")
        System.halt(1)

      {:error, :user_not_present} ->
        IO.puts("Error: Please touch your YubiKey")
        System.halt(1)

      {:error, reason} ->
        IO.puts("Error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  @spec yubikey_list() :: no_return()
  defp yubikey_list do
    case Manager.list_yubikey_credentials() do
      {:ok, []} ->
        IO.puts("No YubiKey credentials enrolled")

      {:ok, creds} ->
        IO.puts("Enrolled YubiKey credentials:")

        Enum.each(creds, fn cred ->
          IO.puts("  - #{cred.credential_id}")
        end)

      {:error, reason} ->
        IO.puts("Error: #{inspect(reason)}")
    end

    System.halt(0)
  end

  @spec yubikey_remove(String.t()) :: no_return()
  defp yubikey_remove(cred_id) do
    case Manager.remove_yubikey_credential(cred_id) do
      :ok ->
        IO.puts("Credential removed")
        System.halt(0)

      {:error, reason} ->
        IO.puts("Error: #{inspect(reason)}")
        System.halt(1)
    end
  end

  @spec yubikey_status() :: no_return()
  defp yubikey_status do
    device_available = Manager.yubikey_available?()
    enrolled = Manager.yubikey_enrolled?()

    IO.puts("YubiKey/FIDO2 Status:")
    IO.puts("  Device available: #{device_available}")
    IO.puts("  YubiKey enrolled: #{enrolled}")

    unless device_available do
      IO.puts("")
      IO.puts("Note: To use YubiKey authentication, you need:")
      IO.puts("  1. A FIDO2/YubiKey 5 series device")
      IO.puts("  2. libfido2 installed (fido2-tools on Linux)")
    end

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
