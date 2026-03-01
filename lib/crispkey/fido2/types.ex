defmodule Crispkey.FIDO2.Types do
  @moduledoc """
  Types for FIDO2/WebAuthn credentials and operations.
  """

  @type credential_id :: binary()
  @type public_key :: binary()
  @type attestation :: binary()
  @type assertion :: binary()

  @type rp_id :: String.t()
  @type user_id :: binary()

  @type credential :: %{
          credential_id: credential_id(),
          public_key: public_key(),
          rp_id: rp_id(),
          user_id: user_id(),
          created_at: DateTime.t()
        }

  @type attestation_object :: %{
          fmt: String.t(),
          auth_data: binary(),
          att_stmt: map()
        }

  @type auth_data :: %{
          rp_id_hash: binary(),
          flags: binary(),
          sign_count: integer(),
          attested_credential_data: map() | nil,
          extensions: map() | nil
        }

  @type assertion_object :: %{
          credential_id: credential_id(),
          auth_data: binary(),
          signature: binary(),
          client_data_json: binary()
        }

  @type client_data :: %{
          type: String.t(),
          challenge: String.t(),
          origin: String.t(),
          cross_origin: boolean() | nil
        }

  @type wrapped_key :: %{
          credential_id: credential_id(),
          public_key: public_key(),
          rp_id: rp_id()
        }

  defstruct [:credential_id, :public_key, :rp_id, :user_id, :created_at]

  defmodule Credential do
    @moduledoc """
    FIDO2 credential struct for storage.
    """
    @enforce_keys [:credential_id, :public_key, :rp_id]
    defstruct [:credential_id, :public_key, :rp_id, :user_id, :created_at]

    @type t :: %__MODULE__{
            credential_id: binary(),
            public_key: binary(),
            rp_id: String.t(),
            user_id: binary() | nil,
            created_at: DateTime.t()
          }
  end

  defmodule Assertion do
    @moduledoc """
    FIDO2 assertion response for authentication.
    """
    @enforce_keys [:credential_id, :auth_data, :signature, :client_data_json]
    defstruct [:credential_id, :auth_data, :signature, :client_data_json]

    @type t :: %__MODULE__{
            credential_id: binary(),
            auth_data: binary(),
            signature: binary(),
            client_data_json: binary()
          }
  end

  defmodule WrappedKey do
    @moduledoc """
    Stored wrapped key data for YubiKey-based authentication.
    """
    @enforce_keys [:credential_id, :public_key, :rp_id]
    defstruct [:credential_id, :public_key, :rp_id]

    @type t :: %__MODULE__{
            credential_id: binary(),
            public_key: binary(),
            rp_id: String.t()
          }
  end
end
