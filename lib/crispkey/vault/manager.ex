defmodule Crispkey.Vault.Manager do
  @moduledoc """
  Manages vault lifecycle: creation, reading, updating, deletion.

  The manager caches the master key in memory for the session duration.
  All vault operations require the master key to be unlocked first.

  Supports YubiKey/FIDO2 authentication in addition to password.
  """

  use GenServer

  alias Crispkey.FIDO2.Client, as: FIDO2Client
  alias Crispkey.FIDO2.Types, as: FIDO2Types
  alias Crispkey.Store.LocalState
  alias Crispkey.Vault.{Crypto, ManifestModule, Types}
  alias Types.{Manifest, Vault, VaultEntry, WrappedKeyPackage}

  @type state :: %{
          master_key: binary() | nil,
          master_salt: binary() | nil,
          manifest: Manifest.t() | nil,
          unlocked: boolean(),
          auth_method: :password | :yubikey | nil,
          auth_methods: [:password | :yubikey],
          yubikey_only: boolean()
        }

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec unlock(String.t()) :: :ok | {:error, :invalid_password}
  def unlock(password) do
    GenServer.call(__MODULE__, {:unlock, password})
  end

  @spec lock() :: :ok
  def lock do
    GenServer.call(__MODULE__, :lock)
  end

  @spec unlocked?() :: boolean()
  def unlocked? do
    GenServer.call(__MODULE__, :unlocked?)
  end

  @spec create_vault(String.t(), String.t() | nil, String.t() | nil, String.t() | nil) ::
          :ok | {:error, term()}
  def create_vault(fingerprint, public_key, secret_key \\ nil, trust \\ nil) do
    GenServer.call(__MODULE__, {:create_vault, fingerprint, public_key, secret_key, trust})
  end

  @spec read_vault(String.t()) :: {:ok, Vault.t()} | {:error, :not_found | :locked}
  def read_vault(fingerprint) do
    GenServer.call(__MODULE__, {:read_vault, fingerprint})
  end

  @spec update_vault(String.t(), map()) :: :ok | {:error, :not_found | :locked}
  def update_vault(fingerprint, updates) do
    GenServer.call(__MODULE__, {:update_vault, fingerprint, updates})
  end

  @spec delete_vault(String.t()) :: :ok | {:error, :not_found}
  def delete_vault(fingerprint) do
    GenServer.call(__MODULE__, {:delete_vault, fingerprint})
  end

  @spec list_vaults() :: {:ok, [VaultEntry.t()]} | {:error, :locked}
  def list_vaults do
    GenServer.call(__MODULE__, :list_vaults)
  end

  @spec get_vault_path(String.t()) :: String.t()
  def get_vault_path(fingerprint) do
    Path.join([vaults_dir(), "#{fingerprint}.vault"])
  end

  @spec get_raw_vault(String.t()) :: {:ok, binary()} | {:error, :not_found}
  def get_raw_vault(fingerprint) do
    path = get_vault_path(fingerprint)

    case File.read(path) do
      {:ok, data} -> {:ok, data}
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec put_raw_vault(String.t(), binary()) :: :ok | {:error, term()}
  def put_raw_vault(fingerprint, data) do
    GenServer.call(__MODULE__, {:put_raw_vault, fingerprint, data})
  end

  @spec initialize(String.t()) :: :ok
  def initialize(password) do
    GenServer.call(__MODULE__, {:initialize, password})
  end

  @spec initialize_yubikey(String.t()) ::
          :ok | {:error, :not_available | :enrollment_failed | term()}
  def initialize_yubikey(pin) do
    GenServer.call(__MODULE__, {:initialize_yubikey, pin})
  end

  @spec get_manifest() :: {:ok, Manifest.t()} | {:error, :locked}
  def get_manifest do
    GenServer.call(__MODULE__, :get_manifest)
  end

  @spec yubikey_available?() :: boolean()
  def yubikey_available? do
    FIDO2Client.device_available?()
  end

  @spec yubikey_enrolled?() :: boolean()
  def yubikey_enrolled? do
    FIDO2Client.enrolled?()
  end

  @spec enroll_yubikey(String.t()) :: :ok | {:error, :not_available | :enrollment_failed | term()}
  def enroll_yubikey(pin) do
    GenServer.call(__MODULE__, {:enroll_yubikey, pin})
  end

  @spec unlock_with_yubikey() ::
          :ok | {:error, :not_enrolled | :user_not_present | :verification_failed | term()}
  def unlock_with_yubikey do
    GenServer.call(__MODULE__, :unlock_with_yubikey)
  end

  @spec auth_method() :: :password | :yubikey | nil
  def auth_method do
    GenServer.call(__MODULE__, :auth_method)
  end

  @spec auth_methods() :: [:password | :yubikey]
  def auth_methods do
    GenServer.call(__MODULE__, :auth_methods)
  end

  @spec yubikey_only?() :: boolean()
  def yubikey_only? do
    GenServer.call(__MODULE__, :yubikey_only?)
  end

  @spec list_yubikey_credentials() :: {:ok, [map()]} | {:error, term()}
  def list_yubikey_credentials do
    case FIDO2Client.list_enrolled() do
      {:ok, keys} ->
        {:ok,
         Enum.map(keys, fn key ->
           %{
             credential_id: Base.encode64(key.credential_id),
             rp_id: key.rp_id
           }
         end)}

      error ->
        error
    end
  end

  @spec remove_yubikey_credential(credential_id :: String.t()) :: :ok | {:error, term()}
  def remove_yubikey_credential(credential_id) do
    cred_id = Base.decode64!(credential_id)
    FIDO2Client.remove_enrolled(cred_id)
  end

  @spec vaults_dir() :: String.t()
  def vaults_dir do
    Path.join(Crispkey.data_dir(), "vaults")
  end

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(_opts) do
    File.mkdir_p!(vaults_dir())

    auth_methods = determine_auth_methods()
    yubikey_only = LocalState.yubikey_only?()

    state =
      try_auto_unlock(%{
        master_key: nil,
        master_salt: nil,
        manifest: nil,
        unlocked: false,
        auth_method: nil,
        auth_methods: auth_methods,
        yubikey_only: yubikey_only
      })

    {:ok, state}
  end

  @spec determine_auth_methods() :: [:password | :yubikey]
  defp determine_auth_methods do
    methods = []
    methods = if master_salt_exists?(), do: [:password | methods], else: methods
    methods = if FIDO2Client.enrolled?(), do: [:yubikey | methods], else: methods
    methods
  end

  @spec master_salt_exists?() :: boolean()
  defp master_salt_exists? do
    path = Path.join(Crispkey.data_dir(), "master_salt")
    File.exists?(path)
  end

  @spec try_auto_unlock(state()) :: state()
  defp try_auto_unlock(state) do
    case System.get_env("CRISPKEY_MASTER_PASSWORD") do
      nil ->
        state

      password ->
        case load_master_salt() do
          {:ok, salt} ->
            master_key = Crypto.derive_master_key(password, salt)

            case load_manifest_encrypted(master_key, salt) do
              {:ok, manifest} ->
                %{
                  master_key: master_key,
                  master_salt: salt,
                  manifest: manifest,
                  unlocked: true
                }

              {:error, _} ->
                state
            end

          {:error, _} ->
            state
        end
    end
  end

  @impl true
  def handle_call({:unlock, password}, _from, state) do
    IO.puts(
      "DEBUG handle_call(:unlock) - yubikey_only: #{state.yubikey_only}, auth_methods: #{inspect(state.auth_methods)}"
    )

    cond do
      state.yubikey_only ->
        IO.puts("DEBUG handle_call(:unlock) - yubikey_only is true, returning error")
        {:reply, {:error, :yubikey_only}, state}

      :yubikey in state.auth_methods ->
        IO.puts("DEBUG handle_call(:unlock) - yubikey in auth_methods, trying yubikey")

        case do_unlock_with_yubikey() do
          {:ok, master_key, manifest} ->
            IO.puts("DEBUG handle_call(:unlock) - yubikey unlock succeeded")

            {:reply, :ok,
             %{
               state
               | master_key: master_key,
                 master_salt: manifest.salt,
                 manifest: manifest,
                 unlocked: true,
                 auth_method: :yubikey
             }}

          {:error, reason} ->
            IO.puts(
              "DEBUG handle_call(:unlock) - yubikey unlock failed: #{inspect(reason)}, trying password"
            )

            unlock_with_password(password, state)
        end

      true ->
        IO.puts("DEBUG handle_call(:unlock) - no yubikey in auth_methods, trying password")
        unlock_with_password(password, state)
    end
  end

  @spec unlock_with_password(String.t(), state()) :: {:reply, term(), state()}
  defp unlock_with_password(password, state) do
    case load_master_salt() do
      {:ok, salt} ->
        master_key = Crypto.derive_master_key(password, salt)

        case load_manifest_encrypted(master_key, salt) do
          {:ok, manifest} ->
            {:reply, :ok,
             %{
               state
               | master_key: master_key,
                 master_salt: salt,
                 manifest: manifest,
                 unlocked: true,
                 auth_method: :password
             }}

          {:error, _} ->
            {:reply, {:error, :invalid_password}, state}
        end

      {:error, :not_initialized} ->
        {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:lock, _from, _state) do
    {:reply, :ok,
     %{
       master_key: nil,
       master_salt: nil,
       manifest: nil,
       unlocked: false,
       auth_method: nil,
       auth_methods: [],
       yubikey_only: false
     }}
  end

  def handle_call(:auth_method, _from, state) do
    {:reply, state.auth_method, state}
  end

  def handle_call(:auth_methods, _from, state) do
    {:reply, state.auth_methods, state}
  end

  def handle_call(:yubikey_only?, _from, state) do
    {:reply, state.yubikey_only, state}
  end

  def handle_call({:enroll_yubikey, pin}, _from, state) do
    if state.unlocked and state.master_key do
      case do_enroll_yubikey(state.master_key, state.master_salt, pin) do
        {:ok, _wrapped_key} ->
          auth_methods = Enum.uniq([:yubikey | state.auth_methods])
          {:reply, :ok, %{state | auth_method: :yubikey, auth_methods: auth_methods}}

        error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call(:unlock_with_yubikey, _from, state) do
    IO.puts("DEBUG: handle_call(:unlock_with_yubikey) - yubikey_only: #{state.yubikey_only}")
    result = do_unlock_with_yubikey()
    IO.puts("DEBUG: unlock_with_yubikey result: #{inspect(result)}")

    case result do
      {:ok, master_key, manifest} ->
        {:reply, :ok,
         %{
           state
           | master_key: master_key,
             master_salt: manifest.salt,
             manifest: manifest,
             unlocked: true,
             auth_method: :yubikey
         }}

      {:error, _} when state.yubikey_only ->
        IO.puts("DEBUG: Returning yubikey_required error")
        {:reply, {:error, :yubikey_required}, state}

      {:error, _} ->
        IO.puts("DEBUG: Returning yubikey_failed error")
        {:reply, {:error, :yubikey_failed}, state}
    end
  end

  def handle_call(:unlocked?, _from, state) do
    {:reply, state.unlocked, state}
  end

  def handle_call({:initialize, password}, _from, state) do
    salt = Crypto.generate_master_salt()
    master_key = Crypto.derive_master_key(password, salt)

    save_master_salt!(salt)
    LocalState.set_yubikey_only(false)

    manifest = %Manifest{
      vaults: %{},
      salt: salt,
      version: 1,
      created_at: DateTime.utc_now(),
      modified_at: DateTime.utc_now()
    }

    save_manifest_encrypted!(manifest, master_key, salt)

    {:reply, :ok,
     %{
       state
       | master_key: master_key,
         master_salt: salt,
         manifest: manifest,
         unlocked: true,
         auth_method: :password,
         auth_methods: [:password],
         yubikey_only: false
     }}
  end

  def handle_call({:initialize_yubikey, pin}, _from, state) do
    if state.unlocked do
      {:reply, {:error, :already_unlocked}, state}
    else
      do_initialize_yubikey(state, pin)
    end
  end

  defp do_initialize_yubikey(state, pin) do
    master_key = :crypto.strong_rand_bytes(32)
    salt = Crypto.generate_master_salt()

    case do_enroll_yubikey(master_key, salt, pin) do
      {:ok, _wrapped_key} ->
        save_master_salt!(salt)
        LocalState.set_yubikey_only(true)

        manifest = %Manifest{
          vaults: %{},
          salt: salt,
          version: 1,
          created_at: DateTime.utc_now(),
          modified_at: DateTime.utc_now()
        }

        save_manifest_encrypted!(manifest, master_key, salt)

        {:reply, :ok,
         %{
           state
           | master_key: master_key,
             master_salt: salt,
             manifest: manifest,
             unlocked: true,
             auth_method: :yubikey,
             auth_methods: [:yubikey],
             yubikey_only: true
         }}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:create_vault, fingerprint, public_key, secret_key, trust}, _from, state) do
    if state.unlocked do
      vault = %Vault{
        fingerprint: fingerprint,
        public_key: public_key,
        secret_key: secret_key,
        trust: trust,
        metadata: %{created_at: DateTime.utc_now()}
      }

      case save_vault(vault, state.master_key) do
        :ok ->
          entry = build_entry(vault)
          vaults = Map.put(state.manifest.vaults, fingerprint, entry)
          manifest = %{state.manifest | vaults: vaults, modified_at: DateTime.utc_now()}
          save_manifest_encrypted!(manifest, state.master_key, state.master_salt)
          {:reply, :ok, %{state | manifest: manifest}}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call({:read_vault, fingerprint}, _from, state) do
    if state.unlocked do
      case load_vault(fingerprint, state.master_key) do
        {:ok, vault} -> {:reply, {:ok, vault}, state}
        {:error, reason} -> {:reply, {:error, reason}, state}
      end
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call({:update_vault, fingerprint, updates}, _from, state) do
    if state.unlocked do
      do_update_vault(fingerprint, updates, state)
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call({:delete_vault, fingerprint}, _from, state) do
    path = get_vault_path(fingerprint)

    case File.rm(path) do
      :ok ->
        vaults = Map.delete(state.manifest.vaults, fingerprint)
        manifest = %{state.manifest | vaults: vaults, modified_at: DateTime.utc_now()}

        if state.unlocked do
          save_manifest_encrypted!(manifest, state.master_key, state.master_salt)
        end

        {:reply, :ok, %{state | manifest: manifest}}

      {:error, :enoent} ->
        {:reply, {:error, :not_found}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:list_vaults, _from, state) do
    if state.unlocked do
      {:reply, {:ok, Map.values(state.manifest.vaults)}, state}
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call({:put_raw_vault, fingerprint, data}, _from, state) do
    path = get_vault_path(fingerprint)

    case File.write(path, data) do
      :ok ->
        hash = Crypto.hash(data)

        entry = %VaultEntry{
          fingerprint: fingerprint,
          hash: hash,
          size: byte_size(data),
          modified: DateTime.utc_now(),
          has_secret: false
        }

        vaults = Map.put(state.manifest.vaults, fingerprint, entry)
        manifest = %{state.manifest | vaults: vaults, modified_at: DateTime.utc_now()}

        if state.unlocked do
          save_manifest_encrypted!(manifest, state.master_key, state.master_salt)
        end

        {:reply, :ok, %{state | manifest: manifest}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:get_manifest, _from, state) do
    if state.unlocked do
      {:reply, {:ok, state.manifest}, state}
    else
      {:reply, {:error, :locked}, state}
    end
  end

  defp do_update_vault(fingerprint, updates, state) do
    case load_vault(fingerprint, state.master_key) do
      {:ok, vault} ->
        updated_vault = merge_vault_updates(vault, updates)
        save_and_reply(updated_vault, state)

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp save_and_reply(updated_vault, state) do
    case save_vault(updated_vault, state.master_key) do
      :ok ->
        entry = build_entry(updated_vault)
        vaults = Map.put(state.manifest.vaults, updated_vault.fingerprint, entry)
        manifest = %{state.manifest | vaults: vaults, modified_at: DateTime.utc_now()}
        save_manifest_encrypted!(manifest, state.master_key, state.master_salt)
        {:reply, :ok, %{state | manifest: manifest}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @spec save_vault(Vault.t(), binary()) :: :ok | {:error, term()}
  defp save_vault(%Vault{} = vault, master_key) do
    vault_key = Crypto.derive_vault_key(master_key, vault.fingerprint)

    bundle =
      Jason.encode!(%{
        fingerprint: vault.fingerprint,
        public: vault.public_key,
        secret: vault.secret_key,
        trust: vault.trust,
        metadata: vault.metadata
      })

    encrypted = Crypto.encrypt_vault(bundle, vault_key)
    path = get_vault_path(vault.fingerprint)
    File.write(path, encrypted)
  end

  @spec load_vault(String.t(), binary()) :: {:ok, Vault.t()} | {:error, :not_found}
  defp load_vault(fingerprint, master_key) do
    path = get_vault_path(fingerprint)

    case File.read(path) do
      {:ok, encrypted} ->
        vault_key = Crypto.derive_vault_key(master_key, fingerprint)

        case Crypto.decrypt_vault(encrypted, vault_key) do
          {:ok, bundle_json} ->
            {:ok, parse_vault_bundle(bundle_json)}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec parse_vault_bundle(String.t()) :: Vault.t()
  defp parse_vault_bundle(json) do
    {:ok, data} = Jason.decode(json)

    %Vault{
      fingerprint: Map.get(data, "fingerprint"),
      public_key: Map.get(data, "public"),
      secret_key: Map.get(data, "secret"),
      trust: Map.get(data, "trust"),
      metadata: Map.get(data, "metadata", %{})
    }
  end

  @spec build_entry(Vault.t()) :: VaultEntry.t()
  defp build_entry(%Vault{} = vault) do
    path = get_vault_path(vault.fingerprint)

    {size, hash} =
      case File.read(path) do
        {:ok, data} -> {byte_size(data), Crypto.hash(data)}
        _ -> {0, ""}
      end

    %VaultEntry{
      fingerprint: vault.fingerprint,
      hash: hash,
      size: size,
      modified: DateTime.utc_now(),
      has_secret: vault.secret_key != nil
    }
  end

  @spec merge_vault_updates(Vault.t(), map()) :: Vault.t()
  defp merge_vault_updates(vault, updates) do
    Enum.reduce(updates, vault, fn
      {:public_key, val}, acc -> %{acc | public_key: val}
      {:secret_key, val}, acc -> %{acc | secret_key: val}
      {:trust, val}, acc -> %{acc | trust: val}
      {:metadata, val}, acc -> %{acc | metadata: Map.merge(acc.metadata, val)}
      _, acc -> acc
    end)
  end

  @spec load_master_salt() :: {:ok, binary()} | {:error, :not_initialized}
  defp load_master_salt do
    path = Path.join(Crispkey.data_dir(), "master_salt")

    case File.read(path) do
      {:ok, salt} -> {:ok, salt}
      {:error, :enoent} -> {:error, :not_initialized}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec save_master_salt!(binary()) :: :ok
  defp save_master_salt!(salt) do
    path = Path.join(Crispkey.data_dir(), "master_salt")
    File.mkdir_p!(Crispkey.data_dir())
    :ok = File.write(path, salt)
  end

  @spec load_manifest_encrypted(binary(), binary()) ::
          {:ok, Manifest.t()} | {:error, term()}
  defp load_manifest_encrypted(master_key, salt) do
    path = Path.join(Crispkey.data_dir(), "manifest.enc")

    case File.read(path) do
      {:ok, encrypted} ->
        manifest_key = Crypto.derive_vault_key(master_key, "manifest")

        case Crypto.decrypt_vault(encrypted, manifest_key) do
          {:ok, json} ->
            {:ok, ManifestModule.from_json(json, salt)}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :enoent} ->
        {:ok, %Manifest{vaults: %{}, salt: salt, version: 1}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec save_manifest_encrypted!(Manifest.t(), binary(), binary()) :: :ok
  defp save_manifest_encrypted!(manifest, master_key, _salt) do
    path = Path.join(Crispkey.data_dir(), "manifest.enc")
    manifest_key = Crypto.derive_vault_key(master_key, "manifest")
    json = ManifestModule.to_json(manifest)
    encrypted = Crypto.encrypt_vault(json, manifest_key)
    :ok = File.write(path, encrypted)
  end

  @spec do_enroll_yubikey(binary(), binary(), String.t()) ::
          {:ok, FIDO2Types.WrappedKey.t()} | {:error, term()}
  defp do_enroll_yubikey(master_key, salt, pin) do
    case FIDO2Client.enroll(pin) do
      {:ok, wrapped_key} ->
        dek = Crypto.generate_dek()
        challenge = Crypto.create_fido2_challenge(dek)

        case FIDO2Client.authenticate(wrapped_key, challenge) do
          {:ok, assertion} ->
            case FIDO2Client.verify_assertion(assertion, challenge, wrapped_key.public_key) do
              :ok ->
                wrapped_pkg =
                  create_wrapped_package(
                    master_key,
                    dek,
                    assertion.signature,
                    salt,
                    wrapped_key.credential_id
                  )

                save_wrapped_package!(wrapped_pkg)
                FIDO2Client.save_enrolled(wrapped_key)
                {:ok, wrapped_key}

              error ->
                error
            end

          error ->
            error
        end

      error ->
        error
    end
  end

  defp create_wrapped_package(master_key, dek, fido2_signature, salt, credential_id) do
    {encrypted_master_key, nonce, tag} = Crypto.wrap_master_key(master_key, dek)
    dek_key = Crypto.hkdf_derive(dek, "crispkey-fido2", 32)

    sig_part =
      binary_part(fido2_signature, 0, min(byte_size(fido2_signature), byte_size(dek_key)))

    wrapped_dek = :crypto.exor(sig_part, dek_key)

    %WrappedKeyPackage{
      encrypted_master_key: encrypted_master_key,
      nonce: nonce,
      tag: tag,
      wrapped_dek: wrapped_dek,
      salt: salt,
      credential_id: credential_id
    }
  end

  @spec save_wrapped_package!(WrappedKeyPackage.t()) :: :ok
  defp save_wrapped_package!(%WrappedKeyPackage{} = pkg) do
    cred_id_b64 = Base.encode64(pkg.credential_id) |> String.replace("/", "_", global: true)
    File.mkdir_p!(wrapped_keys_dir())
    path = Path.join([wrapped_keys_dir(), "#{cred_id_b64}.enc"])

    data = %{
      "encrypted_master_key" => Base.encode64(pkg.encrypted_master_key),
      "nonce" => Base.encode64(pkg.nonce),
      "tag" => Base.encode64(pkg.tag),
      "wrapped_dek" => Base.encode64(pkg.wrapped_dek),
      "salt" => Base.encode64(pkg.salt),
      "credential_id" => Base.encode64(pkg.credential_id)
    }

    File.write!(path, Jason.encode!(data))
  end

  @spec wrapped_keys_dir() :: String.t()
  defp do_unlock_with_yubikey do
    IO.puts("DEBUG: do_unlock_with_yubikey - calling get_wrapped_keys")

    case FIDO2Client.get_wrapped_keys() do
      {:ok, wrapped_keys} ->
        IO.puts("DEBUG: got #{length(wrapped_keys)} wrapped keys")
        try_unlock_with_keys(wrapped_keys)

      {:error, :not_enrolled} ->
        IO.puts("DEBUG: not_enrolled")
        {:error, :not_enrolled}

      error ->
        IO.puts("DEBUG: get_wrapped_keys error: #{inspect(error)}")
        error
    end
  end

  @spec try_unlock_with_keys([FIDO2Types.WrappedKey.t()]) ::
          {:ok, binary(), Manifest.t()} | {:error, term()}
  defp try_unlock_with_keys([]) do
    {:error, :no_keys}
  end

  defp try_unlock_with_keys([wrapped_key | rest]) do
    IO.puts("DEBUG: try_unlock_with_keys - attempting authentication")

    case load_wrapped_package(wrapped_key.credential_id) do
      {:ok, pkg} ->
        IO.puts("DEBUG: loaded wrapped package, calling FIDO2Client.authenticate")

        case FIDO2Client.authenticate(wrapped_key, pkg.encrypted_master_key) do
          {:ok, assertion} ->
            IO.puts("DEBUG: Authentication succeeded, assertion: #{inspect(assertion)}")

            case Crypto.unwrap_with_fido2(
                   %{
                     encrypted_master_key: pkg.encrypted_master_key,
                     nonce: pkg.nonce,
                     tag: pkg.tag,
                     wrapped_dek: pkg.wrapped_dek
                   },
                   assertion.signature,
                   wrapped_key.public_key
                 ) do
              {:ok, master_key} ->
                IO.puts("DEBUG: unwrap_with_fido2 succeeded")
                salt = pkg.salt

                case load_manifest_encrypted(master_key, salt) do
                  {:ok, manifest} -> {:ok, master_key, manifest}
                  error -> error
                end

              error ->
                IO.puts("DEBUG: unwrap_with_fido2 failed: #{inspect(error)}")
                try_unlock_with_keys(rest)
            end

          error ->
            IO.puts("DEBUG: FIDO2Client.authenticate failed: #{inspect(error)}")
            try_unlock_with_keys(rest)
        end

      {:error, reason} ->
        IO.puts("DEBUG: load_wrapped_package failed: #{inspect(reason)}")
        try_unlock_with_keys(rest)
    end
  end

  @spec wrapped_keys_dir() :: String.t()
  defp wrapped_keys_dir do
    Path.join(Crispkey.data_dir(), "wrapped_keys")
  end

  @spec load_wrapped_package(binary()) :: {:ok, WrappedKeyPackage.t()} | {:error, :not_found}
  defp load_wrapped_package(credential_id) do
    # credential_id in WrappedKey is stored as Base64 string, not decoded
    # We need to compare the strings directly, not decode
    IO.puts("DEBUG: load_wrapped_package - credential_id (raw): #{inspect(credential_id)}")

    IO.puts(
      "DEBUG: load_wrapped_package - files in dir: #{inspect(wrapped_keys_dir() |> File.ls!())}"
    )

    # Find the file by matching the Base64 string directly
    found_file =
      Enum.find_value(wrapped_keys_dir() |> File.ls!(), fn filename ->
        base64_part = String.replace_trailing(filename, ".enc", "")
        IO.puts("DEBUG: load_wrapped_package - checking file: #{base64_part}")
        IO.puts("DEBUG: load_wrapped_package - match? #{base64_part == credential_id}")
        if base64_part == credential_id, do: filename
      end)

    case found_file do
      nil ->
        IO.puts("DEBUG: load_wrapped_package - no matching file found, trying legacy")
        load_wrapped_package_legacy(credential_id)

      filename ->
        path = Path.join([wrapped_keys_dir(), filename])
        IO.puts("DEBUG: load_wrapped_package found file: #{path}")

        case File.read(path) do
          {:ok, data} ->
            IO.puts("DEBUG: load_wrapped_package succeeded")
            {:ok, json} = Jason.decode(data)

            {:ok,
             %WrappedKeyPackage{
               encrypted_master_key: Base.decode64!(json["encrypted_master_key"]),
               nonce: Base.decode64!(json["nonce"]),
               tag: Base.decode64!(json["tag"]),
               wrapped_dek: Base.decode64!(json["wrapped_dek"]),
               salt: Base.decode64!(json["salt"]),
               credential_id: Base.decode64!(json["credential_id"])
             }}

          {:error, :enoent} ->
            load_wrapped_package_legacy(credential_id)

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  @spec load_wrapped_package_legacy(binary()) ::
          {:ok, WrappedKeyPackage.t()} | {:error, :not_found}
  defp load_wrapped_package_legacy(_credential_id) do
    IO.puts("DEBUG: load_wrapped_package_legacy - trying legacy path")
    path = Path.join(Crispkey.data_dir(), "wrapped_key.enc")
    IO.puts("DEBUG: load_wrapped_package_legacy path: #{path}")
    IO.puts("DEBUG: load_wrapped_package_legacy file exists?: #{File.exists?(path)}")

    case File.read(path) do
      {:ok, data} ->
        IO.puts("DEBUG: load_wrapped_package_legacy succeeded")
        {:ok, json} = Jason.decode(data)

        {:ok,
         %WrappedKeyPackage{
           encrypted_master_key: Base.decode64!(json["encrypted_master_key"]),
           nonce: Base.decode64!(json["nonce"]),
           tag: Base.decode64!(json["tag"]),
           wrapped_dek: Base.decode64!(json["wrapped_dek"]),
           salt: Base.decode64!(json["salt"]),
           credential_id: Base.decode64!(json["credential_id"])
         }}

      {:error, :enoent} ->
        IO.puts("DEBUG: load_wrapped_package_legacy file not found")
        {:error, :not_found}

      {:error, reason} ->
        IO.puts("DEBUG: load_wrapped_package_legacy error: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
