defmodule Crispkey.FIDO2.Bindings do
  @moduledoc """
  Low-level bindings to YubiKey via Python fido2 library.

  Uses the Python fido2-shim via Port for device communication.
  Requires python-fido2 library: pip install fido2
  """

  alias Crispkey.FIDO2.{Port, Types}

  @rp_id "crispkey"

  @spec available?() :: boolean()
  def available?, do: Port.available?()

  @spec list_credentials() ::
          {:ok, [Types.Credential.t()]} | {:error, :no_device | :not_available}
  def list_credentials do
    case Port.list_devices() do
      {:ok, devices} when is_list(devices) and devices != [] ->
        credentials =
          devices
          |> Enum.map(&build_credential/1)

        {:ok, credentials}

      {:ok, []} ->
        {:error, :no_device}

      {:error, reason} ->
        {:error, reason}

      _ ->
        {:error, :not_available}
    end
  end

  defp build_credential(device) do
    vendor = Map.get(device, "vendor", "Unknown")
    product = Map.get(device, "product", "Unknown")
    path = Map.get(device, "path", "")

    %Types.Credential{
      credential_id: :crypto.hash(:sha256, "#{vendor}#{product}#{path}") |> binary_part(0, 32),
      public_key: <<>>,
      rp_id: @rp_id,
      user_id: <<>>,
      created_at: DateTime.utc_now()
    }
  end

  @spec credential_info(credential_id :: binary()) :: {:ok, map()} | {:error, term()}
  def credential_info(credential_id) when is_binary(credential_id) do
    case Port.credential_info(credential_id, @rp_id) do
      {:ok, info} ->
        {:ok, Map.merge(info, %{rp_id: @rp_id})}

      {:error, reason} ->
        {:error, reason}
    end
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

    case Port.authenticate(cred_id, challenge, rp_id) do
      {:ok, assertion} ->
        {:ok, assertion}

      {:error, reason} when is_binary(reason) ->
        cond do
          String.contains?(reason, "UP") or String.contains?(reason, "user presence") ->
            {:error, :user_not_present}

          String.contains?(reason, "UV") or String.contains?(reason, "user verification") ->
            {:error, :user_verification_failed}

          true ->
            {:error, {:assertion_failed, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
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
    case Port.list_devices() do
      {:ok, devices} when is_list(devices) ->
        {:ok, %{devices: devices, available: true}}

      {:error, reason} ->
        {:error, reason}

      _ ->
        {:ok, %{devices: [], available: false}}
    end
  end
end
