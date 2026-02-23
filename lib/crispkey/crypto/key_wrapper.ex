defmodule Crispkey.Crypto.KeyWrapper do
  @moduledoc """
  Key wrapping using AES-256-GCM with PBKDF2-derived master key.

  ## Wrap Format

  The wrapped binary format is:
  - 32 bytes: salt
  - 12 bytes: nonce
  - 16 bytes: authentication tag
  - N bytes: ciphertext

  ## Parameters

  - PBKDF2 with SHA256, 600,000 iterations
  - AES-256-GCM for encryption
  - Random salt and nonce per wrap
  """

  @salt_len 32
  @nonce_len 12
  @key_len 32
  @tag_len 16
  @iterations 600_000

  @type wrapped_binary :: binary()

  @spec wrap(binary(), String.t()) :: wrapped_binary()
  def wrap(plaintext, passphrase) when is_binary(plaintext) and is_binary(passphrase) do
    salt = :crypto.strong_rand_bytes(@salt_len)
    nonce = :crypto.strong_rand_bytes(@nonce_len)
    key = derive_key(passphrase, salt)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        nonce,
        plaintext,
        <<>>,
        true
      )

    <<salt::binary-size(@salt_len), nonce::binary-size(@nonce_len), tag::binary-size(@tag_len),
      ciphertext::binary>>
  end

  @spec unwrap(binary(), String.t()) :: {:ok, binary()} | {:error, :decryption_failed}
  def unwrap(wrapped, passphrase) when is_binary(wrapped) and is_binary(passphrase) do
    min_len = @salt_len + @nonce_len + @tag_len

    if byte_size(wrapped) < min_len do
      {:error, :decryption_failed}
    else
      do_unwrap(wrapped, passphrase)
    end
  end

  @spec do_unwrap(binary(), String.t()) :: {:ok, binary()} | {:error, :decryption_failed}
  defp do_unwrap(wrapped, passphrase) do
    <<salt::binary-size(@salt_len), nonce::binary-size(@nonce_len), tag::binary-size(@tag_len),
      ciphertext::binary>> = wrapped

    key = derive_key(passphrase, salt)

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           nonce,
           ciphertext,
           <<>>,
           tag,
           false
         ) do
      :error -> {:error, :decryption_failed}
      plaintext -> {:ok, plaintext}
    end
  end

  @spec derive_key(String.t(), binary()) :: binary()
  defp derive_key(passphrase, salt) do
    :crypto.pbkdf2_hmac(:sha256, passphrase, salt, @iterations, @key_len)
  end

  @spec generate_fingerprint(binary()) :: String.t()
  def generate_fingerprint(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end
end
