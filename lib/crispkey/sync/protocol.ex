defmodule Crispkey.Sync.Protocol do
  @moduledoc """
  Sync protocol v2 with encrypted sessions.

  ## Protocol Versions

  - v1: Legacy plaintext protocol (deprecated)
  - v2: Encrypted session protocol with vault sync

  ## v2 Message Flow

      Client                          Server
        │                               │
        │─── HELLO(device_id, session)─►│
        │◄── HELLO(device_id, session)──│
        │                               │
        │─── AUTH(auth_token) [enc] ───►│
        │◄── AUTH_OK [enc] ─────────────│
        │                               │
        │─── MANIFEST_REQUEST [enc] ───►│
        │◄── MANIFEST(manifest) [enc] ──│
        │                               │
        │─── VAULT_REQUEST(fps) [enc] ─►│
        │◄── VAULT_DATA(fp, data) [enc]─│
        │                               │
        │─── GOODBYE [enc] ────────────►│
  """

  alias Crispkey.Sync.{Message, Session}
  alias Crispkey.Vault.Types

  @type message :: Message.t()
  @type session :: Types.Session.t()

  @version 2

  @spec version() :: pos_integer()
  def version, do: @version

  @spec hello_v2(String.t(), binary()) :: map()
  def hello_v2(device_id, session_id) do
    %{
      type: "hello",
      device_id: device_id,
      version: @version,
      session_id: Base.encode64(session_id)
    }
  end

  @spec auth(String.t()) :: Message.Auth.t()
  def auth(password_hash), do: Message.auth(password_hash)

  @spec auth_token(String.t()) :: map()
  def auth_token(token) do
    %{type: "auth_token", token: token}
  end

  @spec auth_ok() :: Message.AuthOk.t()
  def auth_ok, do: Message.auth_ok()

  @spec auth_fail() :: Message.AuthFail.t()
  def auth_fail, do: Message.auth_fail()

  @spec manifest_request() :: map()
  def manifest_request do
    %{type: "manifest_request"}
  end

  @spec manifest(map()) :: map()
  def manifest(manifest_data) do
    %{type: "manifest", data: manifest_data}
  end

  @spec vault_request([String.t()]) :: map()
  def vault_request(fingerprints) do
    %{type: "vault_request", fingerprints: fingerprints}
  end

  @spec vault_data(String.t(), binary()) :: map()
  def vault_data(fingerprint, vault_binary) do
    %{type: "vault_data", fingerprint: fingerprint, data: Base.encode64(vault_binary)}
  end

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

  @spec encode(message() | map()) :: binary()
  def encode(%_{} = msg), do: Message.encode(msg)
  def encode(msg) when is_map(msg), do: encode_map(msg)

  @spec encode_map(map()) :: binary()
  defp encode_map(msg) do
    json = Jason.encode!(msg)
    len = byte_size(json)
    <<len::32, json::binary>>
  end

  @spec decode(binary()) :: {:ok, message() | map()} | {:error, term()}
  def decode(<<len::32, data::binary-size(len)>>) do
    case Jason.decode(data) do
      {:ok, %{"type" => type}}
      when type in ~w(hello auth auth_ok auth_fail inventory request key_data trust_data ack goodbye) ->
        Message.decode(<<len::32, data::binary-size(len)>>)

      {:ok, %{"type" => _} = json} ->
        {:ok, json}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def decode(_), do: {:error, :invalid_format}

  @spec encode_encrypted(message() | map(), session()) :: {binary(), session()}
  def encode_encrypted(msg, session) do
    plaintext =
      case msg do
        %_{} ->
          %{type: msg.__struct__ |> Module.split() |> List.last() |> Macro.underscore()}
          |> Map.merge(Message.to_wire(msg))

        map when is_map(map) ->
          map
      end

    json = Jason.encode!(plaintext)
    Session.encode_encrypted(json, session)
  end

  @spec decode_encrypted(binary(), session()) ::
          {:ok, map(), session()} | {:error, term()}
  def decode_encrypted(binary, session) do
    case Session.decode_encrypted(binary, session) do
      {:ok, json, updated_session} ->
        case Jason.decode(json) do
          {:ok, data} -> {:ok, data, updated_session}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
