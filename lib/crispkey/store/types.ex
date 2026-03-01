defmodule Crispkey.Store.Peer do
  @moduledoc """
  Represents a paired peer device.
  """

  @enforce_keys [:id]
  defstruct [:id, :host, :port, :paired_at]

  @type t :: %__MODULE__{
          id: String.t(),
          host: String.t() | nil,
          port: non_neg_integer() | nil,
          paired_at: DateTime.t() | nil
        }
end

defmodule Crispkey.Store.State do
  @moduledoc """
  Represents the persistent application state.
  """

  @enforce_keys [:device_id]
  defstruct [
    :device_id,
    :sync_password_hash,
    initialized: false,
    peers: %{},
    key_syncs: %{},
    last_sync: nil,
    yubikey_only: false
  ]

  @type t :: %__MODULE__{
          device_id: String.t(),
          initialized: boolean(),
          sync_password_hash: String.t() | nil,
          peers: %{String.t() => Crispkey.Store.Peer.t()},
          key_syncs: %{String.t() => %{String.t() => DateTime.t()}},
          last_sync: DateTime.t() | nil,
          yubikey_only: boolean()
        }
end
