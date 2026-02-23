defmodule Crispkey.GPG.Interface do
  @moduledoc """
  Interface to GPG CLI for key operations.
  """

  alias Crispkey.GPG.{Key, Subkey, UID, Types}

  @type gpg_error :: {:error, {pos_integer(), String.t()}}

  @spec gpg_cmd([String.t()], keyword()) :: {:ok, String.t()} | gpg_error()
  def gpg_cmd(args, opts \\ []) do
    homedir = Keyword.get(opts, :homedir, Crispkey.gpg_homedir())

    cmd("gpg", ["--homedir", homedir | args], opts)
  end

  @spec cmd(String.t(), [String.t()], keyword()) :: {:ok, String.t()} | gpg_error()
  defp cmd(name, args, opts) do
    input = Keyword.get(opts, :input)

    if input do
      cmd_with_stdin(name, args, input)
    else
      case System.cmd(name, args, stderr_to_stdout: true) do
        {output, 0} -> {:ok, output}
        {output, code} -> {:error, {code, output}}
      end
    end
  end

  @spec cmd_with_stdin(String.t(), [String.t()], String.t()) :: {:ok, String.t()} | gpg_error()
  defp cmd_with_stdin(name, args, input) do
    port =
      Port.open({:spawn_executable, System.find_executable(name)}, [
        {:args, args},
        :binary,
        :exit_status,
        :use_stdio,
        :stderr_to_stdout
      ])

    send(port, {self(), {:command, input}})
    send(port, {self(), :close})

    result = collect_port_output(port, "")

    case result do
      {output, 0} -> {:ok, output}
      {output, code} -> {:error, {code, output}}
    end
  end

  @spec collect_port_output(port(), String.t()) :: {String.t(), non_neg_integer()}
  defp collect_port_output(port, acc) do
    receive do
      {^port, {:data, data}} -> collect_port_output(port, acc <> data)
      {^port, {:exit_status, status}} -> {acc, status}
      {^port, :closed} -> {acc, 0}
    after
      30_000 -> {acc, 1}
    end
  end

  @spec list_public_keys(keyword()) :: {:ok, [Key.t()]} | gpg_error()
  def list_public_keys(opts \\ []) do
    case gpg_cmd(["--list-keys", "--with-colons", "--fixed-list-mode"], opts) do
      {:ok, output} -> {:ok, parse_keys(output)}
      error -> error
    end
  end

  @spec list_secret_keys(keyword()) :: {:ok, [Key.t()]} | gpg_error()
  def list_secret_keys(opts \\ []) do
    case gpg_cmd(["--list-secret-keys", "--with-colons", "--fixed-list-mode"], opts) do
      {:ok, output} -> {:ok, parse_keys(output)}
      error -> error
    end
  end

  @spec export_public_key(String.t(), keyword()) :: {:ok, String.t()} | gpg_error()
  def export_public_key(fingerprint, opts \\ []) do
    gpg_cmd(["--armor", "--export", fingerprint], opts)
  end

  @spec export_secret_key(String.t(), keyword()) :: {:ok, String.t()} | gpg_error()
  def export_secret_key(fingerprint, opts \\ []) do
    gpg_cmd(["--armor", "--export-secret-keys", fingerprint], opts)
  end

  @spec import_key(String.t(), keyword()) :: {:ok, String.t()} | gpg_error()
  def import_key(key_data, opts \\ []) do
    gpg_cmd(["--import"], Keyword.put(opts, :input, key_data))
  end

  @spec export_trustdb(keyword()) :: {:ok, String.t()} | gpg_error()
  def export_trustdb(opts \\ []) do
    gpg_cmd(["--export-ownertrust"], opts)
  end

  @spec import_trustdb(String.t(), keyword()) :: {:ok, String.t()} | gpg_error()
  def import_trustdb(trust_data, opts \\ []) do
    gpg_cmd(["--import-ownertrust"], Keyword.put(opts, :input, trust_data))
  end

  @spec parse_keys(String.t()) :: [Key.t()]
  def parse_keys(output) do
    output
    |> String.split("\n")
    |> Enum.reduce({[], nil}, fn line, {keys, current} ->
      fields = String.split(line, ":")

      case List.first(fields) do
        "pub" ->
          key = parse_pub(fields)
          {[key | keys], key}

        "sec" ->
          key = parse_sec(fields)
          {[key | keys], key}

        "uid" when current != nil ->
          uid = parse_uid(fields)
          updated = %{current | uids: [uid | current.uids]}
          {keys, updated}

        "sub" when current != nil ->
          subkey = parse_sub(fields)
          updated = %{current | subkeys: [subkey | current.subkeys]}
          {keys, updated}

        _ ->
          {keys, current}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  @spec parse_pub([String.t()]) :: Key.t()
  defp parse_pub(fields) do
    fingerprint = Enum.at(fields, 4)

    %Key{
      fingerprint: fingerprint,
      key_id: fingerprint && String.slice(fingerprint, -16..-1),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2)),
      uids: [],
      subkeys: [],
      type: :public
    }
  end

  @spec parse_sec([String.t()]) :: Key.t()
  defp parse_sec(fields) do
    fingerprint = Enum.at(fields, 4)

    %Key{
      fingerprint: fingerprint,
      key_id: fingerprint && String.slice(fingerprint, -16..-1),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2)),
      uids: [],
      subkeys: [],
      type: :secret
    }
  end

  @spec parse_uid([String.t()]) :: UID.t()
  defp parse_uid(fields) do
    %UID{
      string: Enum.at(fields, 9),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6))
    }
  end

  @spec parse_sub([String.t()]) :: Subkey.t()
  defp parse_sub(fields) do
    %Subkey{
      fingerprint: Enum.at(fields, 4),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2))
    }
  end

  @spec parse_timestamp(String.t() | nil) :: Types.timestamp()
  defp parse_timestamp(""), do: nil
  defp parse_timestamp(nil), do: nil

  defp parse_timestamp(s) when is_binary(s) do
    case Integer.parse(s) do
      {ts, _} -> DateTime.from_unix!(ts)
      _ -> nil
    end
  end

  @spec parse_int(String.t() | nil) :: pos_integer() | nil
  defp parse_int(""), do: nil
  defp parse_int(nil), do: nil

  defp parse_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, _} -> n
      _ -> nil
    end
  end

  @spec parse_algorithm(String.t() | nil) :: Types.algorithm()
  defp parse_algorithm("1"), do: :rsa
  defp parse_algorithm("17"), do: :dsa
  defp parse_algorithm("19"), do: :ecdsa
  defp parse_algorithm("22"), do: :eddsa
  defp parse_algorithm("16"), do: :elgamal
  defp parse_algorithm(_), do: :unknown
end
