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
          auth_method: :password | :yubikey | nil
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

  @spec initialize_yubikey() :: :ok | {:error, :not_available | :enrollment_failed | term()}
  def initialize_yubikey do
    GenServer.call(__MODULE__, :initialize_yubikey)
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
  def enroll_yubikey(password) do
    GenServer.call(__MODULE__, {:enroll_yubikey, password})
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

    state =
      try_auto_unlock(%{
        master_key: nil,
        master_salt: nil,
        manifest: nil,
        unlocked: false,
        auth_method: nil
      })

    {:ok, state}
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
    if LocalState.yubikey_only?() do
      {:reply, {:error, :yubikey_only}, state}
    else
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
                   unlocked: true
               }}

            {:error, _} ->
              {:reply, {:error, :invalid_password}, state}
          end

        {:error, :not_initialized} ->
          {:reply, {:error, :not_initialized}, state}
      end
    end
  end

  def handle_call(:lock, _from, _state) do
    {:reply, :ok,
     %{master_key: nil, master_salt: nil, manifest: nil, unlocked: false, auth_method: nil}}
  end

  def handle_call(:auth_method, _from, state) do
    {:reply, state.auth_method, state}
  end

  def handle_call({:enroll_yubikey, _password}, _from, state) do
    if state.unlocked and state.master_key do
      case do_enroll_yubikey(state.master_key, state.master_salt) do
        {:ok, _wrapped_key} ->
          {:reply, :ok, %{state | auth_method: :yubikey}}

        error ->
          {:reply, error, state}
      end
    else
      {:reply, {:error, :locked}, state}
    end
  end

  def handle_call(:unlock_with_yubikey, _from, state) do
    case load_master_salt() do
      {:ok, salt} ->
        case do_unlock_with_yubikey(salt) do
          {:ok, master_key, manifest} ->
            {:reply, :ok,
             %{
               state
               | master_key: master_key,
                 master_salt: salt,
                 manifest: manifest,
                 unlocked: true,
                 auth_method: :yubikey
             }}

          error ->
            {:reply, error, state}
        end

      {:error, :not_initialized} ->
        {:reply, {:error, :not_initialized}, state}
    end
  end

  def handle_call(:unlocked?, _from, state) do
    {:reply, state.unlocked, state}
  end

  def handle_call({:initialize, password}, _from, state) do
    salt = Crypto.generate_master_salt()
    master_key = Crypto.derive_master_key(password, salt)

    save_master_salt!(salt)

    manifest = %Manifest{
      vaults: %{},
      salt: salt,
      version: 1,
      created_at: DateTime.utc_now(),
      modified_at: DateTime.utc_now()
    }

    save_manifest_encrypted!(manifest, master_key, salt)

    {:reply, :ok,
     %{state | master_key: master_key, master_salt: salt, manifest: manifest, unlocked: true}}
  end

  def handle_call(:initialize_yubikey, _from, state) do
    if state.unlocked do
      {:reply, {:error, :already_unlocked}, state}
    else
      do_initialize_yubikey(state)
    end
  end

  defp do_initialize_yubikey(state) do
    master_key = :crypto.strong_rand_bytes(32)
    salt = Crypto.generate_master_salt()

    case do_enroll_yubikey(master_key, salt) do
      {:ok, _wrapped_key} ->
        save_master_salt!(salt)

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
             auth_method: :yubikey
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

  @spec do_enroll_yubikey(binary(), binary()) ::
          {:ok, FIDO2Types.WrappedKey.t()} | {:error, term()}
  defp do_enroll_yubikey(master_key, salt) do
    case FIDO2Client.enroll() do
      {:ok, wrapped_key} ->
        dek = Crypto.generate_dek()
        challenge = Crypto.create_fido2_challenge(dek)

        case FIDO2Client.authenticate(wrapped_key, challenge) do
          {:ok, assertion} ->
            case FIDO2Client.verify_assertion(assertion, challenge, wrapped_key.public_key) do
              :ok ->
                wrapped_pkg = create_wrapped_package(master_key, dek, assertion.signature, salt)
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

  defp create_wrapped_package(master_key, dek, fido2_signature, salt) do
    {encrypted_master_key, nonce, tag} = Crypto.wrap_master_key(master_key, dek)
    dek_key = Crypto.hkdf_derive(dek, "crispkey-fido2", 32)
    wrapped_dek = :crypto.exor(fido2_signature, dek_key)

    %WrappedKeyPackage{
      encrypted_master_key: encrypted_master_key,
      nonce: nonce,
      tag: tag,
      wrapped_dek: wrapped_dek,
      salt: salt,
      credential_id: <<>>
    }
  end

  defp save_wrapped_package!(%WrappedKeyPackage{} = pkg) do
    path = Path.join(Crispkey.data_dir(), "wrapped_key.enc")
    File.mkdir_p!(Crispkey.data_dir())

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

  @spec do_unlock_with_yubikey(binary()) :: {:ok, binary(), Manifest.t()} | {:error, term()}
  defp do_unlock_with_yubikey(salt) do
    with {:ok, wrapped_key} <- FIDO2Client.get_wrapped_key(),
         {:ok, pkg} <- load_wrapped_package(),
         {:ok, _assertion} <- FIDO2Client.authenticate(wrapped_key, pkg.encrypted_master_key) do
      case Crypto.unwrap_with_fido2(
             %{
               encrypted_master_key: pkg.encrypted_master_key,
               nonce: pkg.nonce,
               tag: pkg.tag,
               wrapped_dek: pkg.wrapped_dek
             },
             pkg.wrapped_dek,
             wrapped_key.public_key
           ) do
        {:ok, master_key} ->
          case load_manifest_encrypted(master_key, salt) do
            {:ok, manifest} -> {:ok, master_key, manifest}
            error -> error
          end

        error ->
          error
      end
    else
      {:error, :not_enrolled} ->
        {:error, :not_enrolled}

      error ->
        error
    end
  end

  @spec load_wrapped_package() :: {:ok, WrappedKeyPackage.t()} | {:error, :not_found}
  defp load_wrapped_package do
    path = Path.join(Crispkey.data_dir(), "wrapped_key.enc")

    case File.read(path) do
      {:ok, data} ->
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
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
