defmodule Crispkey.FIDO2.Bindings do
  @moduledoc """
  Low-level bindings to libfido2 command-line tools.

  Requires fido2-tools to be installed:
  - Ubuntu: sudo apt install fido2-tools
  - Fedora: sudo dnf install fido2-tools
  - macOS: brew install libfido2

  Uses fido2-token for credential management and fido2-assert for authentication.
  """

  alias Crispkey.FIDO2.Types

  @rp_id "crispkey"

  @spec available?() :: boolean()
  def available? do
    check_fido2_token() && check_fido2_assert()
  end

  defp check_fido2_token do
    System.find_executable("fido2-token") != nil
  end

  defp check_fido2_assert do
    System.find_executable("fido2-assert") != nil
  end

  @spec list_credentials() ::
          {:ok, [Types.Credential.t()]} | {:error, :no_device | :not_available}
  def list_credentials do
    with true <- available?(),
         {output, 0} <- System.cmd("fido2-token", ["-L"]) do
      credentials =
        output
        |> String.split("\n", trim: true)
        |> Enum.flat_map(&parse_token_info/1)
        |> Enum.map(&build_credential/1)

      {:ok, credentials}
    else
      false ->
        {:error, :not_available}

      _ ->
        {:error, :no_device}
    end
  end

  defp parse_token_info(line) do
    case String.split(line, ":", parts: 3) do
      [vendor, product, _desc] ->
        [{String.trim(vendor), String.trim(product)}]

      _ ->
        []
    end
  end

  defp build_credential({vendor, product}) do
    %Types.Credential{
      credential_id: :crypto.hash(:sha256, "#{vendor}#{product}") |> binary_part(0, 32),
      public_key: <<>>,
      rp_id: @rp_id,
      user_id: <<>>,
      created_at: DateTime.utc_now()
    }
  end

  @spec credential_info(credential_id :: binary()) :: {:ok, map()} | {:error, term()}
  def credential_info(credential_id) when is_binary(credential_id) do
    if available?() do
      encoded = Base.encode64(credential_id)

      case System.cmd("fido2-assert", ["-G", @rp_id, "-t", "up", "-t", "uv=disc", encoded]) do
        {output, 0} ->
          {:ok, parse_credential_info(output)}

        {error, _} ->
          {:error, {:credential_info, error}}
      end
    else
      {:error, :not_available}
    end
  end

  defp parse_credential_info(output) do
    %{
      rp_id: @rp_id,
      authenticator: output
    }
  end

  @type assertion_options :: %{
          challenge: binary(),
          credential_id: binary(),
          rp_id: String.t()
        }

  @spec generate_assertion(assertion_options()) ::
          {:ok, Types.Assertion.t()} | {:error, :user_not_present | :invalid_signature | term()}
  def generate_assertion(opts) do
    %{challenge: challenge, credential_id: cred_id, rp_id: rp_id} = opts
    rp_id = rp_id || @rp_id

    encoded_challenge = Base.encode64(challenge)
    encoded_cred_id = Base.encode64(cred_id)

    temp_file = write_temp_challenge(challenge)

    try do
      result =
        System.cmd("fido2-assert", [
          "-d",
          rp_id,
          "-t",
          "up",
          "-t",
          "uv=disc",
          "-h",
          encoded_challenge,
          encoded_cred_id
        ])

      case result do
        {output, 0} ->
          parse_assertion_response(output, cred_id, challenge)

        {error_output, exit_code} when exit_code > 0 ->
          cond do
            String.contains?(error_output, "UP") ->
              {:error, :user_not_present}

            String.contains?(error_output, "UV") ->
              {:error, :user_verification_failed}

            true ->
              {:error, {:assertion_failed, error_output}}
          end
      end
    after
      File.rm(temp_file)
    end
  end

  defp write_temp_challenge(challenge) do
    path = Path.join(System.tmp_dir!(), "crispkey_challenge_#{:rand.uniform(1_000_000)}")
    File.write!(path, challenge)
    path
  end

  defp parse_assertion_response(output, original_cred_id, challenge) do
    lines = String.split(output, "\n", trim: true)

    auth_data =
      lines
      |> Enum.find(&String.starts_with?(&1, "authData: "))
      |> case do
        nil -> <<>>
        line -> line |> String.replace("authData: ", "") |> Base.decode64!()
      end

    signature =
      lines
      |> Enum.find(&String.starts_with?(&1, "signature: "))
      |> case do
        nil -> <<>>
        line -> line |> String.replace("signature: ", "") |> Base.decode64!()
      end

    client_data_json =
      Jason.encode!(%{
        type: "webauthn.get",
        challenge: Base.encode64(challenge),
        origin: "crispkey://localhost",
        crossOrigin: false
      })

    {:ok,
     %Types.Assertion{
       credential_id: original_cred_id,
       auth_data: auth_data,
       signature: signature,
       client_data_json: client_data_json
     }}
  end

  @spec verify_assertion(Types.Assertion.t(), binary(), binary()) :: :ok | {:error, term()}
  def verify_assertion(%Types.Assertion{} = assertion, original_challenge, public_key) do
    verified =
      :crypto.verify(
        :ecdsa,
        :sha256,
        original_challenge,
        assertion.signature,
        [public_key, :ecdsa_prime256v1]
      )

    if verified do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  @spec get_device_info() :: {:ok, map()} | {:error, :no_device | :not_available}
  def get_device_info do
    with true <- available?(),
         {output, 0} <- System.cmd("fido2-token", ["-L"]) do
      devices =
        output
        |> String.split("\n", trim: true)
        |> Enum.map(&parse_device_info/1)

      {:ok, %{devices: devices, available: true}}
    else
      false ->
        {:ok, %{devices: [], available: false}}

      _ ->
        {:error, :no_device}
    end
  end

  defp parse_device_info(line) do
    parts = String.split(line, ":", parts: 3)

    %{
      raw: line,
      vendor_id: Enum.at(parts, 0) |> String.trim(),
      product_id: Enum.at(parts, 1) |> String.trim(),
      description: Enum.at(parts, 2) |> String.trim("")
    }
  end
end
