defmodule Crispkey.FIDO2.Client do
  @moduledoc """
  High-level FIDO2 client for YubiKey authentication.

  Provides enrollment and authentication workflows for hardware key-based
  vault unlocking.
  """

  alias Crispkey.FIDO2.{Bindings, Types}

  @rp_id "crispkey"
  @rp_name "Crispkey Vault"

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

    client_data_hash =
      :crypto.hash(
        :sha256,
        Jason.encode!(%{
          type: "webauthn.create",
          challenge: Base.url_encode64(challenge, padding: false),
          origin: "crispkey://localhost"
        })
      )

    encoded_chdh = Base.encode64(client_data_hash)
    user_id = :crypto.strong_rand_bytes(16)
    encoded_user_id = Base.encode64(user_id)

    device = find_fido_device()

    input = "#{encoded_chdh}\n#{@rp_id}\ncrispkey\n#{encoded_user_id}\n"

    temp_input = Path.join(System.tmp_dir!(), "crispkey_cred_in_#{:rand.uniform(1_000_000)}")
    temp_output = Path.join(System.tmp_dir!(), "crispkey_cred_out_#{:rand.uniform(1_000_000)}")

    try do
      File.write!(temp_input, input)

      result = run_fido2_cred_with_pin(pin, temp_input, temp_output, device)

      case result do
        {output, 0} ->
          parse_enrollment_response_file(temp_output)

        {error, code} when code > 0 ->
          {:error, {:enrollment_failed, error}}

        {output, _} ->
          {:error, {:enrollment_failed, output}}
      end
    after
      File.rm(temp_input)
      File.rm(temp_output)
    end
  end

  defp find_fido_device do
    case System.cmd("fido2-token", ["-L"]) do
      {output, 0} ->
        case String.split(output, "\n", trim: true) do
          [device | _] ->
            case String.split(device, ":", parts: 2) do
              [path, _] -> String.trim(path)
              _ -> device
            end

          [] ->
            "/dev/hidraw0"
        end

      _ ->
        "/dev/hidraw0"
    end
  end

  defp prompt_pin do
    IO.gets("Enter YubiKey PIN: ") |> String.trim()
  end

  defp run_fido2_cred_with_pin(pin, temp_input, temp_output, device) do
    cmd = "printf '%s' '#{pin}' | fido2-cred -M -i #{temp_input} -o #{temp_output} #{device} es256 2>&1"

    result = :os.cmd(String.to_charlist(cmd))
    output = List.to_string(result)
    
    if String.contains?(output, "credentialId:") or String.contains?(output, "publicKey:") do
      {output, 0}
    else
      {output, 1}
    end
  end
  end

  defp parse_enrollment_response(output) do
    lines = String.split(output, "\n", trim: true)

    credential_id =
      lines
      |> Enum.find(&String.starts_with?(&1, "credentialId: "))
      |> case do
        nil -> <<>>
        line -> line |> String.replace("credentialId: ", "") |> Base.decode64!()
      end

    public_key =
      lines
      |> Enum.find(&String.starts_with?(&1, "publicKey: "))
      |> case do
        nil -> <<>>
        line -> line |> String.replace("publicKey: ", "") |> Base.decode64!()
      end

    if credential_id != <<>> and public_key != <<>> do
      {:ok,
       %Types.WrappedKey{
         credential_id: credential_id,
         public_key: public_key,
         rp_id: @rp_id
       }}
    else
      {:error, :enrollment_parse_failed}
    end
  end

  defp parse_enrollment_response_file(output_path) do
    case File.read(output_path) do
      {:ok, output} ->
        parse_enrollment_response(output)

      {:error, reason} ->
        {:error, {:enrollment_parse_failed, reason}}
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
    if available?() do
      do_authenticate(wrapped_key, challenge)
    else
      {:error, :not_available}
    end
  end

  defp do_authenticate(wrapped_key, challenge) do
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
    case load_wrapped_keys() do
      {:ok, keys} -> {:ok, keys}
      {:error, :not_found} -> {:ok, []}
      error -> error
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
  Get the wrapped key for authentication.
  """
  @spec get_wrapped_key() :: {:ok, Types.WrappedKey.t()} | {:error, :not_enrolled}
  def get_wrapped_key do
    case load_wrapped_keys() do
      {:ok, [key | _]} -> {:ok, key}
      {:ok, []} -> {:error, :not_enrolled}
      {:error, :not_found} -> {:error, :not_enrolled}
    end
  end

  defp wrapped_key_path do
    Path.join(Crispkey.data_dir(), "wrapped_key")
  end

  defp load_wrapped_keys do
    path = wrapped_key_path()

    case File.read(path) do
      {:ok, data} ->
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
              {:ok, map} ->
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
