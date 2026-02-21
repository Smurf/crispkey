defmodule Crispkey.GPG.Interface do
  @moduledoc """
  Interface to GPG CLI for key operations.
  """

  def gpg_cmd(args, opts \\ []) do
    homedir = Keyword.get(opts, :homedir, Crispkey.gpg_homedir())
    
    cmd("gpg", ["--homedir", homedir | args], opts)
  end

  defp cmd(name, args, opts) do
    input = Keyword.get(opts, :input)
    
    if input do
      cmd_with_stdin(name, args, input)
    else
      case System.cmd(name, args, [stderr_to_stdout: true]) do
        {output, 0} -> {:ok, output}
        {output, code} -> {:error, {code, output}}
      end
    end
  end

  defp cmd_with_stdin(name, args, input) do
    port = Port.open({:spawn_executable, System.find_executable(name)}, [
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

  defp collect_port_output(port, acc) do
    receive do
      {^port, {:data, data}} -> collect_port_output(port, acc <> data)
      {^port, {:exit_status, status}} -> {acc, status}
      {^port, :closed} -> {acc, 0}
    after
      30_000 -> {acc, 1}
    end
  end

  def list_public_keys(opts \\ []) do
    case gpg_cmd(["--list-keys", "--with-colons", "--fixed-list-mode"], opts) do
      {:ok, output} -> {:ok, parse_keys(output)}
      error -> error
    end
  end

  def list_secret_keys(opts \\ []) do
    case gpg_cmd(["--list-secret-keys", "--with-colons", "--fixed-list-mode"], opts) do
      {:ok, output} -> {:ok, parse_keys(output)}
      error -> error
    end
  end

  def export_public_key(fingerprint, opts \\ []) do
    gpg_cmd(["--armor", "--export", fingerprint], opts)
  end

  def export_secret_key(fingerprint, opts \\ []) do
    gpg_cmd(["--armor", "--export-secret-keys", fingerprint], opts)
  end

  def import_key(key_data, opts \\ []) do
    gpg_cmd(["--import"], Keyword.put(opts, :input, key_data))
  end

  def export_trustdb(opts \\ []) do
    gpg_cmd(["--export-ownertrust"], opts)
  end

  def import_trustdb(trust_data, opts \\ []) do
    gpg_cmd(["--import-ownertrust"], Keyword.put(opts, :input, trust_data))
  end

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
          updated = Map.update!(current, :uids, &[uid | &1])
          {keys, updated}
        
        "sub" when current != nil ->
          subkey = parse_sub(fields)
          updated = Map.update!(current, :subkeys, &[subkey | &1])
          {keys, updated}
        
        _ ->
          {keys, current}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp parse_pub(fields) do
    %{
      fingerprint: Enum.at(fields, 4),
      key_id: Enum.at(fields, 4) |> String.slice(-16..-1),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2)),
      uids: [],
      subkeys: [],
      type: :public
    }
  end

  defp parse_sec(fields) do
    %{
      fingerprint: Enum.at(fields, 4),
      key_id: Enum.at(fields, 4) |> String.slice(-16..-1),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2)),
      uids: [],
      subkeys: [],
      type: :secret
    }
  end

  defp parse_uid(fields) do
    %{
      string: Enum.at(fields, 9),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6))
    }
  end

  defp parse_sub(fields) do
    %{
      fingerprint: Enum.at(fields, 4),
      created_at: parse_timestamp(Enum.at(fields, 5)),
      expires_at: parse_timestamp(Enum.at(fields, 6)),
      algorithm: parse_algorithm(Enum.at(fields, 3)),
      bits: parse_int(Enum.at(fields, 2))
    }
  end

  defp parse_timestamp(""), do: nil
  defp parse_timestamp(s) when is_binary(s) do
    case Integer.parse(s) do
      {ts, _} -> DateTime.from_unix!(ts)
      _ -> nil
    end
  end
  defp parse_timestamp(_), do: nil

  defp parse_int(""), do: nil
  defp parse_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, _} -> n
      _ -> nil
    end
  end
  defp parse_int(_), do: nil

  defp parse_algorithm("1"), do: :rsa
  defp parse_algorithm("17"), do: :dsa
  defp parse_algorithm("19"), do: :ecdsa
  defp parse_algorithm("22"), do: :eddsa
  defp parse_algorithm(_), do: :unknown
end
