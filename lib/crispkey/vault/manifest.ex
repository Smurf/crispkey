defmodule Crispkey.Vault.ManifestModule do
  @moduledoc """
  Manifest management for tracking vault metadata.

  The manifest is stored encrypted alongside the vaults and tracks:
  - Which vaults exist
  - Their checksums (for sync comparison)
  - Their sizes
  - Last modified timestamps
  """

  alias Crispkey.Vault.Types.{Manifest, VaultEntry}

  @spec new(binary()) :: Manifest.t()
  def new(salt \\ nil) do
    %Manifest{
      vaults: %{},
      salt: salt,
      version: 1,
      created_at: DateTime.utc_now(),
      modified_at: DateTime.utc_now()
    }
  end

  @spec add_vault(Manifest.t(), VaultEntry.t()) :: Manifest.t()
  def add_vault(%Manifest{} = manifest, %VaultEntry{} = entry) do
    vaults = Map.put(manifest.vaults, entry.fingerprint, entry)
    %{manifest | vaults: vaults, modified_at: DateTime.utc_now()}
  end

  @spec remove_vault(Manifest.t(), String.t()) :: Manifest.t()
  def remove_vault(%Manifest{} = manifest, fingerprint) do
    vaults = Map.delete(manifest.vaults, fingerprint)
    %{manifest | vaults: vaults, modified_at: DateTime.utc_now()}
  end

  @spec get_vault(Manifest.t(), String.t()) :: VaultEntry.t() | nil
  def get_vault(%Manifest{} = manifest, fingerprint) do
    Map.get(manifest.vaults, fingerprint)
  end

  @spec list_vaults(Manifest.t()) :: [VaultEntry.t()]
  def list_vaults(%Manifest{} = manifest) do
    Map.values(manifest.vaults)
  end

  @spec to_json(Manifest.t()) :: String.t()
  def to_json(%Manifest{} = manifest) do
    data = %{
      version: manifest.version,
      vaults: vaults_to_map(manifest.vaults),
      created_at: manifest.created_at && DateTime.to_iso8601(manifest.created_at),
      modified_at: manifest.modified_at && DateTime.to_iso8601(manifest.modified_at)
    }

    Jason.encode!(data, pretty: true)
  end

  @spec from_json(String.t(), binary() | nil) :: Manifest.t()
  def from_json(json, salt \\ nil) do
    {:ok, data} = Jason.decode(json)

    %Manifest{
      version: Map.get(data, "version", 1),
      vaults: parse_vaults(Map.get(data, "vaults", %{})),
      salt: salt,
      created_at: parse_datetime(Map.get(data, "created_at")),
      modified_at: parse_datetime(Map.get(data, "modified_at"))
    }
  end

  @spec diff(Manifest.t(), Manifest.t()) :: %{
          local_only: [VaultEntry.t()],
          remote_only: [VaultEntry.t()],
          different: [{VaultEntry.t(), VaultEntry.t()}]
        }
  def diff(%Manifest{} = local, %Manifest{} = remote) do
    local_fps = MapSet.new(Map.keys(local.vaults))
    remote_fps = MapSet.new(Map.keys(remote.vaults))

    local_only_fps = MapSet.difference(local_fps, remote_fps)
    remote_only_fps = MapSet.difference(remote_fps, local_fps)
    common_fps = MapSet.intersection(local_fps, remote_fps)

    different =
      common_fps
      |> Enum.filter(fn fp ->
        local_entry = Map.get(local.vaults, fp)
        remote_entry = Map.get(remote.vaults, fp)
        local_entry.hash != remote_entry.hash
      end)
      |> Enum.map(fn fp ->
        {Map.get(local.vaults, fp), Map.get(remote.vaults, fp)}
      end)

    %{
      local_only:
        local_only_fps
        |> Enum.map(&Map.get(local.vaults, &1)),
      remote_only:
        remote_only_fps
        |> Enum.map(&Map.get(remote.vaults, &1)),
      different: different
    }
  end

  @spec merge(Manifest.t(), Manifest.t()) :: Manifest.t()
  def merge(%Manifest{} = local, %Manifest{} = remote) do
    diff_result = diff(local, remote)

    merged_vaults =
      Enum.reduce(diff_result.remote_only, local.vaults, fn entry, acc ->
        Map.put(acc, entry.fingerprint, entry)
      end)

    merged_vaults =
      Enum.reduce(diff_result.different, merged_vaults, fn {local_entry, remote_entry}, acc ->
        if DateTime.compare(
             remote_entry.modified || ~U[1970-01-01 00:00:00Z],
             local_entry.modified || ~U[1970-01-01 00:00:00Z]
           ) == :gt do
          Map.put(acc, remote_entry.fingerprint, remote_entry)
        else
          acc
        end
      end)

    %{local | vaults: merged_vaults, modified_at: DateTime.utc_now()}
  end

  defp vaults_to_map(vaults) do
    for {fp, entry} <- vaults, into: %{} do
      {fp, vault_entry_to_map(entry)}
    end
  end

  defp vault_entry_to_map(%VaultEntry{} = entry) do
    %{
      fingerprint: entry.fingerprint,
      hash: entry.hash,
      size: entry.size,
      modified: entry.modified && DateTime.to_iso8601(entry.modified),
      has_secret: entry.has_secret
    }
  end

  defp parse_vaults(vaults_map) do
    for {fp, data} <- vaults_map, into: %{} do
      {fp, parse_vault_entry(data)}
    end
  end

  defp parse_vault_entry(data) do
    %VaultEntry{
      fingerprint: Map.get(data, "fingerprint"),
      hash: Map.get(data, "hash"),
      size: Map.get(data, "size"),
      modified: parse_datetime(Map.get(data, "modified")),
      has_secret: Map.get(data, "has_secret", false)
    }
  end

  defp parse_datetime(nil), do: nil

  defp parse_datetime(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _offset} -> dt
      _ -> nil
    end
  end

  defp parse_datetime(_), do: nil
end
