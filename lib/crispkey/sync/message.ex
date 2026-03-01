defmodule Crispkey.Sync.Message do
  @moduledoc """
  Wire protocol message types for sync communication.

  All messages are serialized to JSON for wire transmission.
  The decode function safely converts wire data to typed structs.
  """

  @version 2
  def version, do: @version

  defmodule Hello do
    @moduledoc "Handshake message (v2 protocol)."
    defstruct [:device_id, :session_id, version: 2]

    @type t :: %__MODULE__{
            device_id: String.t(),
            session_id: binary() | nil,
            version: 2
          }
  end

  defmodule Auth do
    @moduledoc "Authentication message with password hash."
    defstruct [:password_hash]
    @type t :: %__MODULE__{password_hash: String.t()}
  end

  defmodule AuthOk do
    @moduledoc "Authentication success response."
    defstruct []
    @type t :: %__MODULE__{}
  end

  defmodule AuthFail do
    @moduledoc "Authentication failure response."
    defstruct []
    @type t :: %__MODULE__{}
  end

  defmodule Inventory do
    @moduledoc "Key inventory message."
    defstruct [:keys]
    @type t :: %__MODULE__{keys: [map()]}
  end

  defmodule Request do
    @moduledoc "Key request message."
    defstruct [:fingerprints, :types]
    @type t :: %__MODULE__{fingerprints: [String.t()], types: [:public | :secret | :trust]}
  end

  defmodule KeyData do
    @moduledoc "Key data transfer message."
    defstruct [:fingerprint, :key_type, :data, :metadata]

    @type t :: %__MODULE__{
            fingerprint: String.t(),
            key_type: :public | :secret,
            data: String.t(),
            metadata: map()
          }
  end

  defmodule TrustData do
    @moduledoc "Trust database transfer message."
    defstruct [:data]
    @type t :: %__MODULE__{data: String.t()}
  end

  defmodule Ack do
    @moduledoc "Acknowledgment message."
    defstruct [:fingerprint, :status]
    @type t :: %__MODULE__{fingerprint: String.t() | nil, status: atom() | String.t()}
  end

  defmodule Goodbye do
    @moduledoc "Connection close message."
    defstruct [:reason]
    @type t :: %__MODULE__{reason: atom() | String.t()}
  end

  @type t ::
          Hello.t()
          | Auth.t()
          | AuthOk.t()
          | AuthFail.t()
          | Inventory.t()
          | Request.t()
          | KeyData.t()
          | TrustData.t()
          | Ack.t()
          | Goodbye.t()

  @message_types %{
    "hello" => Hello,
    "auth" => Auth,
    "auth_ok" => AuthOk,
    "auth_fail" => AuthFail,
    "inventory" => Inventory,
    "request" => Request,
    "key_data" => KeyData,
    "trust_data" => TrustData,
    "ack" => Ack,
    "goodbye" => Goodbye
  }

  def message_types, do: @message_types

  @spec auth(String.t()) :: Auth.t()
  def auth(password_hash) do
    %Auth{password_hash: password_hash}
  end

  @spec auth_ok() :: AuthOk.t()
  def auth_ok do
    %AuthOk{}
  end

  @spec auth_fail() :: AuthFail.t()
  def auth_fail do
    %AuthFail{}
  end

  @spec inventory([map()]) :: Inventory.t()
  def inventory(keys) do
    %Inventory{keys: keys}
  end

  @spec request([String.t()], [:public | :secret | :trust]) :: Request.t()
  def request(fingerprints, types \\ [:public, :secret, :trust]) do
    %Request{fingerprints: fingerprints, types: types}
  end

  @spec key_data(String.t(), :public | :secret, String.t(), map()) :: KeyData.t()
  def key_data(fingerprint, key_type, data, metadata \\ %{}) do
    %KeyData{fingerprint: fingerprint, key_type: key_type, data: data, metadata: metadata}
  end

  @spec trust_data(String.t()) :: TrustData.t()
  def trust_data(data) do
    %TrustData{data: data}
  end

  @spec ack(String.t() | nil, atom() | String.t()) :: Ack.t()
  def ack(fingerprint, status) do
    %Ack{fingerprint: fingerprint, status: status}
  end

  @spec goodbye(atom() | String.t()) :: Goodbye.t()
  def goodbye(reason \\ :normal) do
    %Goodbye{reason: reason}
  end

  @doc """
  Encodes a message struct to wire format (4-byte length prefix + JSON).
  """
  @spec encode(t()) :: binary()
  def encode(%_{} = msg) do
    data = to_wire(msg)
    json = Jason.encode!(data)
    len = byte_size(json)
    <<len::32, json::binary>>
  end

  @doc """
  Decodes wire data to a typed message struct.
  Returns {:ok, message} or {:error, reason}.
  """
  @spec decode(binary()) :: {:ok, t()} | {:error, term()}
  def decode(<<len::32, data::binary-size(len)>>) do
    with {:ok, json} <- Jason.decode(data),
         {:ok, msg} <- from_wire(json) do
      {:ok, msg}
    else
      {:error, %Jason.DecodeError{} = e} -> {:error, {:json_decode_error, e}}
      {:error, reason} -> {:error, reason}
    end
  end

  def decode(_), do: {:error, :invalid_format}

  @doc """
  Converts a message struct to a wire-compatible map (atoms become strings).
  """
  @spec to_wire(t()) :: map()
  def to_wire(%Hello{device_id: device_id, version: version, session_id: session_id}) do
    map = %{"type" => "hello", "device_id" => device_id, "version" => version}

    if session_id do
      Map.put(map, "session_id", Base.encode64(session_id))
    else
      map
    end
  end

  def to_wire(%Auth{password_hash: hash}) do
    %{"type" => "auth", "password_hash" => hash}
  end

  def to_wire(%AuthOk{}) do
    %{"type" => "auth_ok"}
  end

  def to_wire(%AuthFail{}) do
    %{"type" => "auth_fail"}
  end

  def to_wire(%Inventory{keys: keys}) do
    %{"type" => "inventory", "keys" => keys}
  end

  def to_wire(%Request{fingerprints: fps, types: types}) do
    %{"type" => "request", "fingerprints" => fps, "types" => Enum.map(types, &Atom.to_string/1)}
  end

  def to_wire(%KeyData{fingerprint: fp, key_type: type, data: data, metadata: meta}) do
    %{
      "type" => "key_data",
      "fingerprint" => fp,
      "key_type" => Atom.to_string(type),
      "data" => data,
      "metadata" => meta
    }
  end

  def to_wire(%TrustData{data: data}) do
    %{"type" => "trust_data", "data" => data}
  end

  def to_wire(%Ack{fingerprint: fp, status: status}) do
    %{"type" => "ack", "fingerprint" => fp, "status" => maybe_atom_to_string(status)}
  end

  def to_wire(%Goodbye{reason: reason}) do
    %{"type" => "goodbye", "reason" => maybe_atom_to_string(reason)}
  end

  @doc """
  Converts a wire map (from JSON) to a typed message struct.
  Uses explicit key atomization to prevent atom table exhaustion.
  """
  @spec from_wire(map()) :: {:ok, t()} | {:error, term()}
  def from_wire(%{"type" => type} = data) when is_map(data) do
    case Map.get(@message_types, type) do
      nil -> {:error, {:unknown_message_type, type}}
      module -> from_wire_type(module, data)
    end
  end

  def from_wire(_), do: {:error, :missing_type_field}

  @spec from_wire_type(module(), map()) :: {:ok, t()} | {:error, term()}
  defp from_wire_type(Hello, %{
         "device_id" => device_id,
         "version" => version,
         "session_id" => session_id_b64
       }) do
    with :ok <- validate_device_id(device_id),
         :ok <- validate_version(version),
         {:ok, session_id} <- decode_session_id(session_id_b64) do
      {:ok, %Hello{device_id: device_id, version: version, session_id: session_id}}
    end
  end

  defp from_wire_type(Hello, %{"device_id" => device_id, "version" => version}) do
    with :ok <- validate_device_id(device_id),
         :ok <- validate_version(version) do
      {:ok, %Hello{device_id: device_id, version: version, session_id: nil}}
    end
  end

  defp from_wire_type(Hello, %{"device_id" => device_id}) do
    with :ok <- validate_device_id(device_id) do
      {:ok, %Hello{device_id: device_id, version: @version, session_id: nil}}
    end
  end

  defp from_wire_type(Auth, %{"password_hash" => hash}) when is_binary(hash) do
    {:ok, %Auth{password_hash: hash}}
  end

  defp from_wire_type(AuthOk, %{}) do
    {:ok, %AuthOk{}}
  end

  defp from_wire_type(AuthFail, %{}) do
    {:ok, %AuthFail{}}
  end

  defp from_wire_type(Inventory, %{"keys" => keys}) when is_list(keys) do
    {:ok, %Inventory{keys: keys}}
  end

  defp from_wire_type(Request, %{"fingerprints" => fps, "types" => types})
       when is_list(fps) and is_list(types) do
    type_atoms = Enum.map(types, &string_to_key_type/1)
    {:ok, %Request{fingerprints: fps, types: type_atoms}}
  end

  defp from_wire_type(Request, %{"fingerprints" => fps}) when is_list(fps) do
    {:ok, %Request{fingerprints: fps, types: [:public, :secret, :trust]}}
  end

  defp from_wire_type(KeyData, %{
         "fingerprint" => fp,
         "key_type" => type,
         "data" => data,
         "metadata" => meta
       })
       when is_binary(fp) and is_binary(type) and is_binary(data) do
    {:ok,
     %KeyData{fingerprint: fp, key_type: string_to_key_type(type), data: data, metadata: meta}}
  end

  defp from_wire_type(KeyData, %{"fingerprint" => fp, "key_type" => type, "data" => data})
       when is_binary(fp) and is_binary(type) and is_binary(data) do
    {:ok,
     %KeyData{fingerprint: fp, key_type: string_to_key_type(type), data: data, metadata: %{}}}
  end

  defp from_wire_type(TrustData, %{"data" => data}) when is_binary(data) do
    {:ok, %TrustData{data: data}}
  end

  defp from_wire_type(Ack, data) do
    fp = Map.get(data, "fingerprint")
    status = Map.get(data, "status")
    {:ok, %Ack{fingerprint: fp, status: status}}
  end

  defp from_wire_type(Goodbye, data) do
    reason = Map.get(data, "reason", "normal")
    {:ok, %Goodbye{reason: maybe_string_to_atom(reason)}}
  end

  defp from_wire_type(_module, _data), do: {:error, :invalid_message_fields}

  defp decode_session_id(nil), do: {:ok, nil}
  defp decode_session_id(b64) when is_binary(b64), do: Base.decode64(b64)
  defp decode_session_id(_), do: {:error, :invalid_session_id}

  @spec validate_device_id(term()) :: :ok | {:error, :invalid_device_id}
  defp validate_device_id(id) when is_binary(id) and byte_size(id) > 0, do: :ok
  defp validate_device_id(_), do: {:error, :invalid_device_id}

  @spec validate_version(term()) :: :ok | {:error, :invalid_version}
  defp validate_version(v) when is_integer(v) and v > 0, do: :ok
  defp validate_version(_), do: {:error, :invalid_version}

  @spec string_to_key_type(String.t()) :: :public | :secret | :trust | String.t()
  defp string_to_key_type("public"), do: :public
  defp string_to_key_type("secret"), do: :secret
  defp string_to_key_type("trust"), do: :trust
  defp string_to_key_type(other), do: other

  @spec maybe_atom_to_string(atom() | term()) :: String.t() | term()
  defp maybe_atom_to_string(v) when is_atom(v), do: Atom.to_string(v)
  defp maybe_atom_to_string(v), do: v

  @spec maybe_string_to_atom(String.t() | term()) :: atom() | term()
  defp maybe_string_to_atom("normal"), do: :normal
  defp maybe_string_to_atom("error"), do: :error
  defp maybe_string_to_atom(v) when is_binary(v), do: v
  defp maybe_string_to_atom(v), do: v
end
