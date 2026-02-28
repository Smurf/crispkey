defmodule Crispkey.Sync.Session do
  @moduledoc """
  Encrypted sync session management.

  Sessions use a derived key from the sync password to encrypt all
  communication between nodes. Each session has a unique session ID
  and uses counter-based nonces for message encryption.

  ## Session Key Derivation

      session_key = HKDF-SHA256(sync_password, session_id, 32)

  ## Message Format

  All messages after the initial HELLO are encrypted:
      [4 bytes: length][encrypted_payload]

  Encrypted payload:
      [12 bytes: nonce][16 bytes: auth tag][ciphertext]
  """

  alias Crispkey.Vault.{Crypto, Types}
  alias Types.Session

  @spec create(String.t()) :: Session.t()
  def create(sync_password) do
    session_id = Crypto.generate_session_id()
    session_key = Crypto.derive_session_key(sync_password, session_id)

    %Session{
      session_id: session_id,
      session_key: session_key,
      peer_id: nil,
      nonce_counter: 0,
      established_at: DateTime.utc_now()
    }
  end

  @spec create_with_id(String.t(), binary()) :: Session.t()
  def create_with_id(sync_password, session_id) do
    session_key = Crypto.derive_session_key(sync_password, session_id)

    %Session{
      session_id: session_id,
      session_key: session_key,
      peer_id: nil,
      nonce_counter: 0,
      established_at: DateTime.utc_now()
    }
  end

  @spec encrypt(binary(), Session.t()) :: {binary(), Session.t()}
  def encrypt(plaintext, %Session{} = session) when is_binary(plaintext) do
    Crypto.encrypt_session_message(plaintext, session)
  end

  @spec decrypt(binary(), Session.t()) ::
          {:ok, binary(), Session.t()} | {:error, :decryption_failed}
  def decrypt(encrypted, %Session{} = session) when is_binary(encrypted) do
    Crypto.decrypt_session_message(encrypted, session)
  end

  @spec encode_encrypted(binary(), Session.t()) :: {binary(), Session.t()}
  def encode_encrypted(plaintext, session) do
    {encrypted, updated_session} = encrypt(plaintext, session)
    len = byte_size(encrypted)
    {<<len::32, encrypted::binary>>, updated_session}
  end

  @spec decode_encrypted(binary(), Session.t()) ::
          {:ok, binary(), Session.t()} | {:error, term()}
  def decode_encrypted(<<len::32, data::binary-size(len)>>, session) do
    decrypt(data, session)
  end

  def decode_encrypted(_, _), do: {:error, :invalid_format}

  @spec compute_auth_token(Session.t()) :: binary()
  def compute_auth_token(%Session{} = session) do
    :crypto.mac(:hmac, :sha256, session.session_key, session.session_id)
    |> Base.encode64()
  end

  @spec verify_auth_token(Session.t(), String.t()) :: boolean()
  def verify_auth_token(%Session{} = session, token) do
    expected = compute_auth_token(session)
    Crypto.constant_time_compare(expected, token)
  end
end
