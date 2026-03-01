defmodule Crispkey.Vault.Types do
  @moduledoc """
  Type definitions for vault system.
  """

  @type auth_method :: :password | :yubikey | :hybrid

  defmodule WrappedKeyPackage do
    @moduledoc """
    Contains the master key wrapped for YubiKey authentication.
    """
    defstruct [
      :encrypted_master_key,
      :nonce,
      :tag,
      :wrapped_dek,
      :salt,
      :credential_id
    ]

    @type t :: %__MODULE__{
            encrypted_master_key: binary(),
            nonce: binary(),
            tag: binary(),
            wrapped_dek: binary(),
            salt: binary(),
            credential_id: binary()
          }
  end

  defmodule Vault do
    @moduledoc """
    Represents a single encrypted vault containing a GPG key.
    """
    @enforce_keys [:fingerprint]
    defstruct [
      :fingerprint,
      :public_key,
      :secret_key,
      :trust,
      metadata: %{}
    ]

    @type t :: %__MODULE__{
            fingerprint: String.t(),
            public_key: String.t() | nil,
            secret_key: String.t() | nil,
            trust: String.t() | nil,
            metadata: map()
          }
  end

  defmodule VaultEntry do
    @moduledoc """
    Entry in the manifest representing vault metadata.
    """
    @enforce_keys [:fingerprint, :hash]
    defstruct [
      :fingerprint,
      :hash,
      :size,
      :modified,
      :has_secret
    ]

    @type t :: %__MODULE__{
            fingerprint: String.t(),
            hash: String.t(),
            size: non_neg_integer(),
            modified: DateTime.t() | nil,
            has_secret: boolean()
          }
  end

  defmodule Manifest do
    @moduledoc """
    Manifest tracking all vaults and their metadata.
    """
    defstruct [
      :vaults,
      :salt,
      version: 1,
      created_at: nil,
      modified_at: nil
    ]

    @type t :: %__MODULE__{
            vaults: %{String.t() => VaultEntry.t()},
            salt: binary() | nil,
            version: pos_integer(),
            created_at: DateTime.t() | nil,
            modified_at: DateTime.t() | nil
          }
  end

  defmodule Session do
    @moduledoc """
    Sync session state with encrypted communication.
    """
    @enforce_keys [:session_id, :session_key]
    defstruct [
      :session_id,
      :session_key,
      :peer_id,
      :nonce_counter,
      established_at: nil
    ]

    @type t :: %__MODULE__{
            session_id: binary(),
            session_key: binary(),
            peer_id: String.t() | nil,
            nonce_counter: non_neg_integer(),
            established_at: DateTime.t() | nil
          }
  end
end
