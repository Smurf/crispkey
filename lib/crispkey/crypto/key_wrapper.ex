defmodule Crispkey.Crypto.KeyWrapper do
  @moduledoc """
  Key wrapping using AES-256-GCM with PBKDF2-derived master key.
  """

  @salt_len 32
  @nonce_len 12
  @key_len 32
  @iterations 600_000

  def wrap(plaintext, passphrase) when is_binary(plaintext) and is_binary(passphrase) do
    salt = :crypto.strong_rand_bytes(@salt_len)
    nonce = :crypto.strong_rand_bytes(@nonce_len)
    key = derive_key(passphrase, salt)
    
    {ciphertext, tag} = :crypto.crypto_one_time_aead(
      :aes_256_gcm,
      key,
      nonce,
      plaintext,
      <<>>,
      true
    )
    
    <<salt::binary-size(@salt_len), nonce::binary-size(@nonce_len), tag::binary-size(16), ciphertext::binary>>
  end

  def unwrap(wrapped, passphrase) when is_binary(wrapped) and is_binary(passphrase) do
    <<salt::binary-size(@salt_len), nonce::binary-size(@nonce_len), tag::binary-size(16), ciphertext::binary>> = wrapped
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

  defp derive_key(passphrase, salt) do
    :crypto.pbkdf2_hmac(:sha256, passphrase, salt, @iterations, @key_len)
  end

  def generate_fingerprint(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end
end
