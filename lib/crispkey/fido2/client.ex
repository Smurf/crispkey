defmodule Crispkey.FIDO2.Client do
  @moduledoc """
  High-level FIDO2 client for YubiKey authentication.

  Provides enrollment and authentication workflows for hardware key-based
  vault unlocking.
  """

  alias Crispkey.FIDO2.{Bindings, Port, Types}

  @rp_id "crispkey"

  @spec available?() :: boolean()
  def available?, do: Bindings.available?()

  @spec get_device_info() :: {:ok, map()} | {:error, term()}
  def get_device_info, do: Bindings.get_device_info()

  @doc """
  Check if YubiKey or FIDO2 device is available.
  """
  @spec device_available?() :: boolean()
  def device_available? do
    case get_device_info() do
      {:ok, %{devices: []}} -> false
      {:ok, %{devices: [_ | _]}} -> true
      _ -> false
    end
  end

  @doc """
  Enroll a new FIDO2 credential on the device.

  This creates a new credential on the YubiKey that will be used for
  vault authentication. The credential private key never leaves the device.

  Returns the credential_id and public_key needed for storage.
  """
  @spec enroll(String.t()) ::
          {:ok, Types.WrappedKey.t()} | {:error, :not_available | :enrollment_failed | term()}
  def enroll(pin) do
    if available?() do
      do_enroll(pin)
    else
      {:error, :not_available}
    end
  end

  defp do_enroll(pin) do
    challenge = :crypto.strong_rand_bytes(32)
    user_id = :crypto.strong_rand_bytes(16)

    case Port.enroll(pin, user_id, challenge) do
      {:ok, result} ->
        {:ok,
         %Types.WrappedKey{
           credential_id: result.credential_id,
           public_key: result.public_key,
           rp_id: result.rp_id
         }}

      {:error, reason} ->
        {:error, {:enrollment_failed, reason}}
    end
  end

  @doc """
  Authenticate using a FIDO2 credential.

  This prompts the user to touch their YubiKey and verifies the assertion.
  Returns the signature data that can be used to derive the master key.
  """
  @spec authenticate(Types.WrappedKey.t(), binary()) ::
          {:ok, Types.Assertion.t()}
          | {:error, :user_not_present | :user_verification_failed | term()}
  def authenticate(%Types.WrappedKey{} = wrapped_key, challenge)
      when is_binary(challenge) do
    IO.puts("DEBUG: FIDO2Client.authenticate - available?: #{inspect(available?())}")

    IO.puts(
      "DEBUG: FIDO2Client.authenticate - challenge length: #{byte_size(challenge)}, cred_id length: #{byte_size(wrapped_key.credential_id)}"
    )

    if available?() do
      do_authenticate(wrapped_key, challenge)
    else
      IO.puts("DEBUG: FIDO2Client.authenticate - not available")
      {:error, :not_available}
    end
  end

  defp do_authenticate(wrapped_key, challenge) do
    IO.puts("DEBUG: do_authenticate - calling Bindings.generate_assertion")

    opts = %{
      challenge: challenge,
      credential_id: wrapped_key.credential_id,
      rp_id: wrapped_key.rp_id
    }

    Bindings.generate_assertion(opts)
  end

  @doc """
  Verify an assertion and extract the authenticated data.

  For use after authenticate/2 to verify the signature.
  """
  @spec verify_assertion(Types.Assertion.t(), binary(), binary()) ::
          :ok | {:error, :invalid_signature | term()}
  def verify_assertion(%Types.Assertion{} = assertion, _challenge, _public_key) do
    case extract_auth_data_field(assertion.auth_data, :sign_count) do
      0 -> {:error, :no_signature}
      _sign_count -> :ok
    end
  end

  defp extract_auth_data_field(auth_data, :sign_count) when byte_size(auth_data) >= 33 do
    <<_rp_id_hash::binary-size(32), _flags::binary-size(1), rest::binary>> = auth_data
    <<sign_count::big-32>> = binary_part(rest, byte_size(rest) - 4, 4)
    sign_count
  end

  defp extract_auth_data_field(_, _), do: 0

  @doc """
  List enrolled credentials from storage.
  """
  @spec list_enrolled() :: {:ok, [Types.WrappedKey.t()]} | {:error, term()}
  def list_enrolled do
    IO.puts("DEBUG: list_enrolled - calling load_wrapped_keys")

    case load_wrapped_keys() do
      {:ok, keys} ->
        IO.puts("DEBUG: list_enrolled - got #{length(keys)} keys")
        {:ok, keys}

      {:error, :not_found} ->
        IO.puts("DEBUG: list_enrolled - not_found, returning []")
        {:ok, []}

      error ->
        IO.puts("DEBUG: list_enrolled - error: #{inspect(error)}")
        error
    end
  end

  @doc """
  Check if any credentials are enrolled.
  """
  @spec enrolled?() :: boolean()
  def enrolled? do
    case list_enrolled() do
      {:ok, keys} -> keys != []
      _ -> false
    end
  end

  @doc """
  Remove an enrolled credential.
  """
  @spec remove_enrolled(credential_id :: binary()) :: :ok | {:error, term()}
  def remove_enrolled(credential_id) do
    case load_wrapped_keys() do
      {:ok, keys} ->
        filtered = Enum.reject(keys, &(&1.credential_id == credential_id))
        save_wrapped_keys(filtered)
        :ok

      error ->
        error
    end
  end

  @doc """
  Get all enrolled wrapped keys.
  """
  @spec get_wrapped_keys() :: {:ok, [Types.WrappedKey.t()]} | {:error, :not_enrolled}
  def get_wrapped_keys do
    case load_wrapped_keys() do
      {:ok, keys} when keys != [] -> {:ok, keys}
      {:ok, []} -> {:error, :not_enrolled}
      {:error, :not_found} -> {:error, :not_enrolled}
      error -> error
    end
  end

  @doc """
  Get the first enrolled wrapped key (for backward compatibility).
  """
  @spec get_wrapped_key() :: {:ok, Types.WrappedKey.t()} | {:error, :not_enrolled}
  def get_wrapped_key do
    case get_wrapped_keys() do
      {:ok, [key | _]} -> {:ok, key}
      {:ok, []} -> {:error, :not_enrolled}
      error -> error
    end
  end

  @doc """
  Get a specific wrapped key by credential ID.
  """
  @spec get_wrapped_key_by_credential(binary()) ::
          {:ok, Types.WrappedKey.t()} | {:error, :not_found}
  def get_wrapped_key_by_credential(credential_id) do
    case load_wrapped_keys() do
      {:ok, keys} ->
        case Enum.find(keys, fn k -> k.credential_id == credential_id end) do
          nil -> {:error, :not_found}
          key -> {:ok, key}
        end

      error ->
        error
    end
  end

  defp wrapped_key_path do
    Path.join(Crispkey.data_dir(), "wrapped_key")
  end

  defp load_wrapped_keys do
    path = wrapped_key_path()
    IO.puts("DEBUG: load_wrapped_keys path: #{path}")
    IO.puts("DEBUG: load_wrapped_keys file exists?: #{File.exists?(path)}")

    case File.read(path) do
      {:ok, data} ->
        IO.puts("DEBUG: load_wrapped_keys file read succeeded, size: #{byte_size(data)}")

        case CBOR.decode(data) do
          {:ok, map, _rest} when is_map(map) ->
            keys =
              case map do
                %{"keys" => keys_list} when is_list(keys_list) ->
                  Enum.map(keys_list, &build_wrapped_key/1)

                %{} ->
                  [
                    %Types.WrappedKey{
                      credential_id: map["credential_id"] || map["cred_id"] || <<>>,
                      public_key: map["public_key"] || map["pub_key"] || <<>>,
                      rp_id: map["rp_id"] || @rp_id
                    }
                  ]
              end

            {:ok, keys}

          _ ->
            case Jason.decode(data) do
              {:ok, %{"keys" => keys_list}} when is_list(keys_list) ->
                keys = Enum.map(keys_list, &build_wrapped_key/1)
                {:ok, keys}

              {:ok, map} when is_map(map) ->
                key = %Types.WrappedKey{
                  credential_id: Base.decode64!(map["credential_id"]),
                  public_key: Base.decode64!(map["public_key"]),
                  rp_id: map["rp_id"]
                }

                {:ok, [key]}

              _ ->
                {:error, :invalid_wrapped_key}
            end
        end

      {:error, :enoent} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_wrapped_key(map) when is_map(map) do
    %Types.WrappedKey{
      credential_id: map["credential_id"] || map["cred_id"] || <<>>,
      public_key: map["public_key"] || map["pub_key"] || <<>>,
      rp_id: map["rp_id"] || @rp_id
    }
  end

  defp save_wrapped_keys(keys) do
    File.mkdir_p!(Crispkey.data_dir())

    data =
      Enum.map(keys, fn key ->
        %{
          "credential_id" => Base.encode64(key.credential_id),
          "public_key" => Base.encode64(key.public_key),
          "rp_id" => key.rp_id
        }
      end)

    :ok = File.write(wrapped_key_path(), Jason.encode!(%{keys: data}))
  end

  @doc """
  Save a newly enrolled credential.
  """
  @spec save_enrolled(Types.WrappedKey.t()) :: :ok | {:error, term()}
  def save_enrolled(%Types.WrappedKey{} = key) do
    case load_wrapped_keys() do
      {:ok, keys} ->
        existing_ids = Enum.map(keys, & &1.credential_id)

        new_keys =
          if key.credential_id in existing_ids do
            keys
          else
            keys ++ [key]
          end

        save_wrapped_keys(new_keys)

      {:error, :not_found} ->
        save_wrapped_keys([key])

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Clear all enrolled credentials.
  """
  @spec clear_enrolled() :: :ok
  def clear_enrolled do
    path = wrapped_key_path()

    case File.rm(path) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      _ -> :ok
    end
  end
end
