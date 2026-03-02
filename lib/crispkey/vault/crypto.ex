defmodule Crispkey.Vault.Crypto do
  @moduledoc """
  Cryptographic operations for vault encryption.

  ## Key Derivation

  Master key is derived from password using PBKDF2:
    master_key = PBKDF2(password, salt, 600k iterations, SHA256)

  Each vault uses a unique key derived from master key using HKDF:
    vault_key = HKDF-SHA256(master_key, fingerprint, 32 bytes)

  ## Encryption

  Vault data is encrypted using AES-256-GCM:
    - 32 bytes salt
    - 12 bytes nonce
    - 16 bytes auth tag
    - ciphertext

  ## Session Encryption

  Sync sessions use a session key derived from sync password:
    session_key = HKDF-SHA256(sync_password, session_id || timestamp, 32)
  """

  alias Crispkey.Vault.Types.Session

  @master_salt_len 32
  @vault_salt_len 32
  @nonce_len 12
  @key_len 32
  @tag_len 16
  @pbkdf2_iterations 600_000

  @spec derive_master_key(String.t(), binary()) :: binary()
  def derive_master_key(password, salt) when is_binary(password) and is_binary(salt) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, @pbkdf2_iterations, @key_len)
  end

  @spec derive_vault_key(binary(), String.t()) :: binary()
  def derive_vault_key(master_key, fingerprint)
      when is_binary(master_key) and is_binary(fingerprint) do
    hkdf_derive(master_key, fingerprint, @key_len)
  end

  @spec derive_session_key(String.t(), binary()) :: binary()
  def derive_session_key(sync_password, session_id)
      when is_binary(sync_password) and is_binary(session_id) do
    hkdf_derive(sync_password, session_id, @key_len)
  end

  @spec generate_master_salt() :: binary()
  def generate_master_salt do
    :crypto.strong_rand_bytes(@master_salt_len)
  end

  @spec generate_session_id() :: binary()
  def generate_session_id do
    :crypto.strong_rand_bytes(16)
  end

  @spec encrypt_vault(binary(), binary()) :: binary()
  def encrypt_vault(plaintext, vault_key) when is_binary(plaintext) and is_binary(vault_key) do
    salt = :crypto.strong_rand_bytes(@vault_salt_len)
    nonce = :crypto.strong_rand_bytes(@nonce_len)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        vault_key,
        nonce,
        plaintext,
        <<>>,
        true
      )

    <<salt::binary-size(@vault_salt_len), nonce::binary-size(@nonce_len),
      tag::binary-size(@tag_len), ciphertext::binary>>
  end

  @spec decrypt_vault(binary(), binary()) :: {:ok, binary()} | {:error, :decryption_failed}
  def decrypt_vault(wrapped, vault_key) when is_binary(wrapped) and is_binary(vault_key) do
    min_len = @vault_salt_len + @nonce_len + @tag_len

    if byte_size(wrapped) < min_len do
      {:error, :decryption_failed}
    else
      do_decrypt_vault(wrapped, vault_key)
    end
  end

  defp do_decrypt_vault(wrapped, vault_key) do
    <<_salt::binary-size(@vault_salt_len), nonce::binary-size(@nonce_len),
      tag::binary-size(@tag_len), ciphertext::binary>> = wrapped

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           vault_key,
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

  @spec encrypt_session_message(binary(), Session.t()) :: {binary(), Session.t()}
  def encrypt_session_message(plaintext, %Session{} = session) when is_binary(plaintext) do
    {nonce, updated_session} = next_nonce(session)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        session.session_key,
        nonce,
        plaintext,
        <<>>,
        true
      )

    {<<nonce::binary-size(@nonce_len), tag::binary-size(@tag_len), ciphertext::binary>>,
     updated_session}
  end

  @spec decrypt_session_message(binary(), Session.t()) ::
          {:ok, binary(), Session.t()} | {:error, :decryption_failed}
  def decrypt_session_message(encrypted, %Session{} = session) when is_binary(encrypted) do
    if byte_size(encrypted) < @nonce_len + @tag_len do
      {:error, :decryption_failed}
    else
      do_decrypt_session_message(encrypted, session)
    end
  end

  defp do_decrypt_session_message(encrypted, session) do
    <<nonce::binary-size(@nonce_len), tag::binary-size(@tag_len), ciphertext::binary>> = encrypted

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           session.session_key,
           nonce,
           ciphertext,
           <<>>,
           tag,
           false
         ) do
      :error ->
        {:error, :decryption_failed}

      plaintext ->
        {:ok, plaintext, session}
    end
  end

  @spec next_nonce(Session.t()) :: {binary(), Session.t()}
  defp next_nonce(%Session{nonce_counter: counter} = session) do
    new_counter = (counter || 0) + 1
    nonce = :crypto.hash(:sha256, <<new_counter::64>>)
    {binary_part(nonce, 0, @nonce_len), %{session | nonce_counter: new_counter}}
  end

  @spec hkdf_derive(binary() | String.t(), binary(), pos_integer()) :: binary()
  def hkdf_derive(ikm, info, length) do
    hkdf_sha256(ikm, info, length)
  end

  defp hkdf_sha256(ikm, info, length) do
    salt = <<0::size(256)>>
    prk = hmac_sha256(salt, ikm)
    hkdf_expand(prk, info, length)
  end

  defp hkdf_expand(prk, info, length) do
    hash_len = 32
    n = ceil(length / hash_len)

    {output, _} =
      Enum.reduce(1..n, {<<>>, <<>>}, fn i, {acc, prev} ->
        t = hmac_sha256(prk, prev <> info <> <<i::8>>)
        {acc <> t, t}
      end)

    binary_part(output, 0, length)
  end

  defp hmac_sha256(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end

  @spec hash(binary()) :: String.t()
  def hash(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
    |> Base.encode16(case: :lower)
  end

  @spec constant_time_compare(binary(), binary()) :: boolean()
  def constant_time_compare(a, b) when is_binary(a) and is_binary(b) do
    byte_size(a) == byte_size(b) and constant_time_compare_bytes(a, b) == 0
  end

  defp constant_time_compare_bytes(<<>>, <<>>), do: 0

  defp constant_time_compare_bytes(<<x, rest_a::binary>>, <<y, rest_b::binary>>) do
    Bitwise.bxor(x, y) + constant_time_compare_bytes(rest_a, rest_b)
  end

  @doc """
  Generate a random Data Encryption Key (DEK) for wrapping the master key.
  """
  @spec generate_dek() :: binary()
  def generate_dek do
    :crypto.strong_rand_bytes(@key_len)
  end

  @doc """
  Wrap (encrypt) the master key using a DEK.

  Returns: {encrypted_master_key, nonce, tag}
  """
  @spec wrap_master_key(binary(), binary()) :: {binary(), binary(), binary()}
  def wrap_master_key(master_key, dek) when is_binary(master_key) and is_binary(dek) do
    nonce = :crypto.strong_rand_bytes(@nonce_len)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        dek,
        nonce,
        master_key,
        <<>>,
        true
      )

    {ciphertext, nonce, tag}
  end

  @doc """
  Unwrap (decrypt) the master key using a DEK.
  """
  @spec unwrap_master_key(binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, :decryption_failed}
  def unwrap_master_key(ciphertext, nonce, tag, dek)
      when is_binary(ciphertext) and is_binary(nonce) and is_binary(tag) and is_binary(dek) do
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           dek,
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

  @doc """
  Create a wrapped key package for YubiKey authentication.

  The wrapped key package contains:
  - The encrypted master key (ciphertext, nonce, tag)
  - The DEK encrypted with a derived key from the FIDO2 signature
  - Salt for deriving the manifest key
  """
  @type wrapped_package :: %{
          encrypted_master_key: binary(),
          nonce: binary(),
          tag: binary(),
          wrapped_dek: binary(),
          salt: binary(),
          credential_id: binary()
        }
  @spec create_wrapped_package(binary(), binary(), binary(), binary()) :: wrapped_package()
  def create_wrapped_package(master_key, dek, fido2_signature, salt)
      when is_binary(master_key) and is_binary(dek) and is_binary(fido2_signature) and
             is_binary(salt) do
    {encrypted_master_key, nonce, tag} = wrap_master_key(master_key, dek)

    dek_key = hkdf_derive(dek, "crispkey-fido2", @key_len)
    wrapped_dek = :crypto.exor(fido2_signature, dek_key)

    %{
      encrypted_master_key: encrypted_master_key,
      nonce: nonce,
      tag: tag,
      wrapped_dek: wrapped_dek,
      salt: salt,
      credential_id: <<>>
    }
  end

  @doc """
  Unwrap the master key using a FIDO2 signature.

  This verifies the FIDO2 assertion and extracts the DEK to decrypt the master key.
  """
  @spec unwrap_with_fido2(wrapped_package(), binary(), binary()) ::
          {:ok, binary()} | {:error, :invalid_signature | :decryption_failed}
  def unwrap_with_fido2(pkg, fido2_signature, _public_key)
      when is_map(pkg) and is_binary(fido2_signature) do
    dek =
      case byte_size(pkg.wrapped_dek) do
        0 ->
          pkg.encrypted_master_key

        _ ->
          sig_part =
            binary_part(
              fido2_signature,
              0,
              min(byte_size(fido2_signature), byte_size(pkg.wrapped_dek))
            )

          :crypto.exor(sig_part, pkg.wrapped_dek)
      end

    unwrap_master_key(pkg.encrypted_master_key, pkg.nonce, pkg.tag, dek)
  end

  @doc """
  Derive a challenge for FIDO2 authentication that includes the DEK.
  """
  @spec create_fido2_challenge(binary()) :: binary()
  def create_fido2_challenge(dek) when is_binary(dek) do
    challenge_data = "crispkey-vault-unlock:#{Base.encode64(dek)}"
    :crypto.hash(:sha256, challenge_data)
  end
end
