defmodule Crispkey.Merge.Engine do
  @moduledoc """
  Merge engine for reconciling key changes from multiple devices.
  """

  def merge(local_key, remote_key) do
    conflicts = detect_conflicts(local_key, remote_key)
    
    if Enum.empty?(conflicts) do
      do_merge(local_key, remote_key)
    else
      {:conflict, conflicts}
    end
  end

  defp detect_conflicts(local, remote) do
    []
    |> detect_uid_conflicts(local, remote)
    |> detect_subkey_conflicts(local, remote)
    |> detect_expiry_conflicts(local, remote)
  end

  defp detect_uid_conflicts(conflicts, local, remote) do
    local_uids = MapSet.new(local[:uids] || [], & &1.string)
    remote_uids = MapSet.new(remote[:uids] || [], & &1.string)
    
    common = MapSet.intersection(local_uids, remote_uids)
    
    local_new = MapSet.difference(local_uids, common)
    remote_new = MapSet.difference(remote_uids, common)
    
    if MapSet.size(local_new) > 0 and MapSet.size(remote_new) > 0 do
      [%{type: :uids, local: MapSet.to_list(local_new), remote: MapSet.to_list(remote_new)} | conflicts]
    else
      conflicts
    end
  end

  defp detect_subkey_conflicts(conflicts, local, remote) do
    local_subs = MapSet.new(local[:subkeys] || [], & &1.fingerprint)
    remote_subs = MapSet.new(remote[:subkeys] || [], & &1.fingerprint)
    
    local_new = MapSet.difference(local_subs, remote_subs)
    remote_new = MapSet.difference(remote_subs, local_subs)
    
    if MapSet.size(local_new) > 0 and MapSet.size(remote_new) > 0 do
      [%{type: :subkeys, local: MapSet.to_list(local_new), remote: MapSet.to_list(remote_new)} | conflicts]
    else
      conflicts
    end
  end

  defp detect_expiry_conflicts(conflicts, local, remote) do
    if local[:expires_at] != remote[:expires_at] and
       local[:expires_at] != nil and remote[:expires_at] != nil do
      [%{type: :expiry, local: local[:expires_at], remote: remote[:expires_at]} | conflicts]
    else
      conflicts
    end
  end

  defp do_merge(local, remote) do
    merged = %{
      fingerprint: local[:fingerprint] || remote[:fingerprint],
      uids: merge_uids(local[:uids] || [], remote[:uids] || []),
      subkeys: merge_subkeys(local[:subkeys] || [], remote[:subkeys] || []),
      expires_at: latest_expiry(local[:expires_at], remote[:expires_at])
    }
    
    {:ok, merged}
  end

  defp merge_uids(local_uids, remote_uids) do
    local_set = MapSet.new(local_uids, & &1.string)
    
    remote_uids
    |> Enum.filter(fn uid -> not MapSet.member?(local_set, uid.string) end)
    |> Enum.concat(local_uids)
  end

  defp merge_subkeys(local_subs, remote_subs) do
    local_set = MapSet.new(local_subs, & &1.fingerprint)
    
    remote_subs
    |> Enum.filter(fn sub -> not MapSet.member?(local_set, sub.fingerprint) end)
    |> Enum.concat(local_subs)
  end

  defp latest_expiry(nil, remote), do: remote
  defp latest_expiry(local, nil), do: local
  defp latest_expiry(local, remote) do
    case DateTime.compare(local, remote) do
      :gt -> local
      _ -> remote
    end
  end
end
