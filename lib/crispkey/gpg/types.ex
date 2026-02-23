defmodule Crispkey.GPG.Types do
  @moduledoc """
  Type definitions for GPG key data structures.
  """

  @type algorithm :: :rsa | :dsa | :ecdsa | :eddsa | :elgamal | :unknown
  @type key_type :: :public | :secret
  @type timestamp :: DateTime.t() | nil
end

defmodule Crispkey.GPG.UID do
  @moduledoc """
  Represents a GPG user ID.
  """

  defstruct [:string, :created_at, :expires_at]

  @type t :: %__MODULE__{
          string: String.t() | nil,
          created_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil
        }
end

defmodule Crispkey.GPG.Subkey do
  @moduledoc """
  Represents a GPG subkey.
  """

  defstruct [:fingerprint, :created_at, :expires_at, :algorithm, :bits]

  @type t :: %__MODULE__{
          fingerprint: String.t() | nil,
          created_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          algorithm: Crispkey.GPG.Types.algorithm(),
          bits: pos_integer() | nil
        }
end

defmodule Crispkey.GPG.Key do
  @moduledoc """
  Represents a GPG key (public or secret).
  """

  defstruct [
    :fingerprint,
    :key_id,
    :created_at,
    :expires_at,
    :algorithm,
    :bits,
    uids: [],
    subkeys: [],
    type: :public
  ]

  @type t :: %__MODULE__{
          fingerprint: String.t() | nil,
          key_id: String.t() | nil,
          created_at: DateTime.t() | nil,
          expires_at: DateTime.t() | nil,
          algorithm: Crispkey.GPG.Types.algorithm(),
          bits: pos_integer() | nil,
          uids: [Crispkey.GPG.UID.t()],
          subkeys: [Crispkey.GPG.Subkey.t()],
          type: Crispkey.GPG.Types.key_type()
        }
end
