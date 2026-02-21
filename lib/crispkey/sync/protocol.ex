defmodule Crispkey.Sync.Protocol do
  @moduledoc """
  Sync protocol message definitions and serialization.
  """

  @version 1

  def version, do: @version

  def hello(device_id) do
    %{type: :hello, version: @version, device_id: device_id}
  end

  def auth(fingerprint, signature) do
    %{type: :auth, fingerprint: fingerprint, signature: signature}
  end

  def auth_ok(session_key) do
    %{type: :auth_ok, session_key: session_key}
  end

  def inventory(keys) do
    %{type: :inventory, keys: keys}
  end

  def request(fingerprints, types \\ [:public, :secret, :trust]) do
    %{type: :request, fingerprints: fingerprints, types: types}
  end

  def key_data(fingerprint, key_type, wrapped_data, metadata) do
    %{type: :key_data, fingerprint: fingerprint, key_type: key_type, data: wrapped_data, metadata: metadata}
  end

  def trust_data(data) do
    %{type: :trust_data, data: data}
  end

  def ack(fingerprint, status) do
    %{type: :ack, fingerprint: fingerprint, status: status}
  end

  def goodbye(reason \\ :normal) do
    %{type: :goodbye, reason: reason}
  end

  def encode(msg) do
    data = Jason.encode!(msg)
    len = byte_size(data)
    <<len::32, data::binary>>
  end

  def decode(<<len::32, data::binary-size(len)>>) do
    {:ok, Jason.decode!(data, keys: :atoms)}
  end

  def decode(_), do: :error
end
