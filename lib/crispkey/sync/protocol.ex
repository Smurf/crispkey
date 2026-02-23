defmodule Crispkey.Sync.Protocol do
  @moduledoc """
  Sync protocol message definitions and serialization.

  Delegates to Crispkey.Sync.Message for typed message handling.
  This module exists for backward compatibility.
  """

  alias Crispkey.Sync.Message

  @type message :: Message.t()

  @spec version() :: pos_integer()
  def version, do: Message.version()

  @spec hello(String.t()) :: Message.Hello.t()
  def hello(device_id), do: Message.hello(device_id)

  @spec auth(String.t()) :: Message.Auth.t()
  def auth(password_hash), do: Message.auth(password_hash)

  @spec auth_ok() :: Message.AuthOk.t()
  def auth_ok, do: Message.auth_ok()

  @spec auth_fail() :: Message.AuthFail.t()
  def auth_fail, do: Message.auth_fail()

  @spec inventory([map()]) :: Message.Inventory.t()
  def inventory(keys), do: Message.inventory(keys)

  @spec request([String.t()], [:public | :secret | :trust]) :: Message.Request.t()
  def request(fingerprints, types \\ [:public, :secret, :trust]) do
    Message.request(fingerprints, types)
  end

  @spec key_data(String.t(), :public | :secret, String.t(), map()) :: Message.KeyData.t()
  def key_data(fingerprint, key_type, data, metadata \\ %{}) do
    Message.key_data(fingerprint, key_type, data, metadata)
  end

  @spec trust_data(String.t()) :: Message.TrustData.t()
  def trust_data(data), do: Message.trust_data(data)

  @spec ack(String.t() | nil, atom() | String.t()) :: Message.Ack.t()
  def ack(fingerprint, status), do: Message.ack(fingerprint, status)

  @spec goodbye(atom() | String.t()) :: Message.Goodbye.t()
  def goodbye(reason \\ :normal), do: Message.goodbye(reason)

  @spec encode(message()) :: binary()
  def encode(%_{} = msg), do: Message.encode(msg)

  @spec decode(binary()) :: {:ok, message()} | {:error, term()}
  def decode(<<_len::32, _data::binary>> = binary), do: Message.decode(binary)
  def decode(_), do: {:error, :invalid_format}
end
