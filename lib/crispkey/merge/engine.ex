defmodule Crispkey.Merge.Engine do
  @moduledoc """
  Merge engine for reconciling key changes from multiple devices.
  """

  alias Crispkey.GPG.Key

  @type conflict :: %{
          type: :uids | :subkeys | :expiry,
          local: term(),
          remote: term()
        }

  @type merge_result ::
          {:ok, Key.t()}
          | {:conflict, [conflict()]}

  @spec merge(Key.t() | map(), Key.t() | map()) :: merge_result()
  def merge(local_key, remote_key) do
    conflicts = detect_conflicts(local_key, remote_key)

    if Enum.empty?(conflicts) do
      do_merge(local_key, remote_key)
    else
      {:conflict, conflicts}
    end
  end

  @spec detect_conflicts(Key.t() | map(), Key.t() | map()) :: [conflict()]
  defp detect_conflicts(local, remote) do
    []
    |> detect_uid_conflicts(local, remote)
    |> detect_subkey_conflicts(local, remote)
    |> detect_expiry_conflicts(local, remote)
  end

  @spec detect_uid_conflicts([conflict()], Key.t() | map(), Key.t() | map()) :: [conflict()]
  defp detect_uid_conflicts(conflicts, local, remote) do
    local_uids = MapSet.new(get_uids(local), &get_uid_string/1)
    remote_uids = MapSet.new(get_uids(remote), &get_uid_string/1)

    common = MapSet.intersection(local_uids, remote_uids)

    local_new = MapSet.difference(local_uids, common)
    remote_new = MapSet.difference(remote_uids, common)

    if MapSet.size(local_new) > 0 and MapSet.size(remote_new) > 0 do
      [
        %{type: :uids, local: MapSet.to_list(local_new), remote: MapSet.to_list(remote_new)}
        | conflicts
      ]
    else
      conflicts
    end
  end

  @spec detect_subkey_conflicts([conflict()], Key.t() | map(), Key.t() | map()) :: [conflict()]
  defp detect_subkey_conflicts(conflicts, local, remote) do
    local_subs = MapSet.new(get_subkeys(local), &get_subkey_fingerprint/1)
    remote_subs = MapSet.new(get_subkeys(remote), &get_subkey_fingerprint/1)

    local_new = MapSet.difference(local_subs, remote_subs)
    remote_new = MapSet.difference(remote_subs, local_subs)

    if MapSet.size(local_new) > 0 and MapSet.size(remote_new) > 0 do
      [
        %{type: :subkeys, local: MapSet.to_list(local_new), remote: MapSet.to_list(remote_new)}
        | conflicts
      ]
    else
      conflicts
    end
  end

  @spec detect_expiry_conflicts([conflict()], Key.t() | map(), Key.t() | map()) :: [conflict()]
  defp detect_expiry_conflicts(conflicts, local, remote) do
    local_expiry = get_expiry(local)
    remote_expiry = get_expiry(remote)

    if local_expiry != remote_expiry and local_expiry != nil and remote_expiry != nil do
      [%{type: :expiry, local: local_expiry, remote: remote_expiry} | conflicts]
    else
      conflicts
    end
  end

  @spec do_merge(Key.t() | map(), Key.t() | map()) :: {:ok, map()}
  defp do_merge(local, remote) do
    merged = %{
      fingerprint: get_fingerprint(local) || get_fingerprint(remote),
      uids: merge_uids(get_uids(local), get_uids(remote)),
      subkeys: merge_subkeys(get_subkeys(local), get_subkeys(remote)),
      expires_at: latest_expiry(get_expiry(local), get_expiry(remote))
    }

    {:ok, merged}
  end

  @spec merge_uids([map()], [map()]) :: [map()]
  defp merge_uids(local_uids, remote_uids) do
    local_set = MapSet.new(local_uids, &get_uid_string/1)

    remote_uids
    |> Enum.filter(fn uid -> not MapSet.member?(local_set, get_uid_string(uid)) end)
    |> Enum.concat(local_uids)
  end

  @spec merge_subkeys([map()], [map()]) :: [map()]
  defp merge_subkeys(local_subs, remote_subs) do
    local_set = MapSet.new(local_subs, &get_subkey_fingerprint/1)

    remote_subs
    |> Enum.filter(fn sub -> not MapSet.member?(local_set, get_subkey_fingerprint(sub)) end)
    |> Enum.concat(local_subs)
  end

  @spec latest_expiry(DateTime.t() | nil, DateTime.t() | nil) :: DateTime.t() | nil
  defp latest_expiry(nil, remote), do: remote
  defp latest_expiry(local, nil), do: local

  defp latest_expiry(local, remote) do
    case DateTime.compare(local, remote) do
      :gt -> local
      _ -> remote
    end
  end

  @spec get_uids(Key.t() | map()) :: [map()]
  defp get_uids(%Key{uids: uids}), do: uids
  defp get_uids(%{uids: uids}), do: uids
  defp get_uids(_), do: []

  @spec get_subkeys(Key.t() | map()) :: [map()]
  defp get_subkeys(%Key{subkeys: subkeys}), do: subkeys
  defp get_subkeys(%{subkeys: subkeys}), do: subkeys
  defp get_subkeys(_), do: []

  @spec get_expiry(Key.t() | map()) :: DateTime.t() | nil
  defp get_expiry(%Key{expires_at: expires_at}), do: expires_at
  defp get_expiry(%{expires_at: expires_at}), do: expires_at
  defp get_expiry(_), do: nil

  @spec get_fingerprint(Key.t() | map()) :: String.t() | nil
  defp get_fingerprint(%Key{fingerprint: fp}), do: fp
  defp get_fingerprint(%{fingerprint: fp}), do: fp
  defp get_fingerprint(_), do: nil

  @spec get_uid_string(map()) :: String.t()
  defp get_uid_string(%{string: s}), do: s
  defp get_uid_string(%{"string" => s}), do: s
  defp get_uid_string(_), do: ""

  @spec get_subkey_fingerprint(map()) :: String.t()
  defp get_subkey_fingerprint(%{fingerprint: fp}), do: fp
  defp get_subkey_fingerprint(%{"fingerprint" => fp}), do: fp
  defp get_subkey_fingerprint(_), do: ""
end
